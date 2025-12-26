// Package api provides utilities for interacting with the Dex OAuth2/OIDC provider,
// including login, callback, token exchange, and health check operations.
package dex

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Connector is the type for supported OAuth providers (e.g., Google, GitHub, Mock).
type Connector string

// Supported connector types.
const (
	// Atlassian Crowd connector: https://dexidp.io/docs/connectors/atlassian-crowd/
	ConnectorAtlassianCrowd Connector = "atlassian-crowd"
	// Auth Proxy connector: https://dexidp.io/docs/connectors/authproxy/
	ConnectorAuthProxy Connector = "authproxy"
	// Bitbucket Cloud connector: https://dexidp.io/docs/connectors/bitbucketcloud/
	ConnectorBitbucketCloud Connector = "bitbucket-cloud"
	// Gitea connector: https://dexidp.io/docs/connectors/gitea/
	ConnectorGitea Connector = "gitea"
	// GitHub connector: https://dexidp.io/docs/connectors/github/
	ConnectorGitHub Connector = "github"
	// GitLab connector: https://dexidp.io/docs/connectors/gitlab/
	ConnectorGitLab Connector = "gitlab"
	// Google connector: https://dexidp.io/docs/connectors/google/
	ConnectorGoogle Connector = "google"
	// Keystone connector: https://dexidp.io/docs/connectors/keystone/
	ConnectorKeystone Connector = "keystone"
	// LDAP connector: https://dexidp.io/docs/connectors/ldap/
	ConnectorLDAP Connector = "ldap"
	// LinkedIn connector: https://dexidp.io/docs/connectors/linkedin/
	ConnectorLinkedIn Connector = "linkedin"
	// Microsoft connector: https://dexidp.io/docs/connectors/microsoft/
	ConnectorMicrosoft Connector = "microsoft"
	// Mock connector (for testing or development)
	ConnectorMock Connector = "mock"
	// OAuth connector: https://dexidp.io/docs/connectors/oauth/
	ConnectorOAuth Connector = "oauth"
	// OpenID Connect (OIDC) connector: https://dexidp.io/docs/connectors/oidc/
	ConnectorOpenIDConnect Connector = "oidc"
	// OpenShift connector: https://dexidp.io/docs/connectors/openshift/
	ConnectorOpenShift Connector = "openshift"
	// SAML connector: https://dexidp.io/docs/connectors/saml/
	ConnectorSAML Connector = "saml"
)

// Dex wraps the OAuth2/OIDC client and related configuration for authentication flows.
type Dex struct {
	c              *http.Client          // HTTP client for requests
	oauth2cfg      *oauth2.Config        // OAuth2 configuration
	provider       *oidc.Provider        // OIDC provider
	verifier       *oidc.IDTokenVerifier // Token verifier
	callbackURL    string                // Callback URL for OAuth2
	healthURL      string                // Health check URL
	clientIPHeader string                // Header name for client IP address
}

// NewDex creates a new Dex client with the given HTTP transport, OAuth2 config, and OIDC provider.
func NewDex(
	rt http.RoundTripper,
	oauth2cfg *oauth2.Config,
	provider *oidc.Provider,
	clientIPHeader string,
	timeout time.Duration,
) (*Dex, error) {
	u, err := url.Parse(oauth2cfg.Endpoint.AuthURL)
	if err != nil {
		return nil, err
	}

	authURLHost := u.Host
	authURLPath := u.Path

	// Construct callback URL.
	u.Path = path.Join(path.Dir(authURLPath), "callback")
	u.ForceQuery = true // so we can avoid one extra ?
	u.RawQuery = ""     // callback call will append one
	callbackURL := u.String()

	// Construct healthcheck URL.
	u.Path = path.Join(path.Dir(authURLPath), "healthz")
	u.ForceQuery = false
	healthURL := u.String()

	c := &http.Client{
		Transport: rt,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow redirects to auth URL only.
			if req.URL.Host == authURLHost && strings.HasPrefix(req.URL.Path, authURLPath) {
				// Needed for redirecting ?connector_id to /connector_id.
				return nil
			}
			return http.ErrUseLastResponse
		},
	}

	// The verifier uses the same HTTP client c which only allows internal redirects.
	// This is safe unless the keys endpoint starts redirecting elsewhere.
	verifier := provider.VerifierContext(oidc.ClientContext(context.Background(), c),
		&oidc.Config{ClientID: oauth2cfg.ClientID})

	dex := &Dex{
		c:              c,
		oauth2cfg:      oauth2cfg,
		provider:       provider,
		verifier:       verifier,
		callbackURL:    callbackURL,
		healthURL:      healthURL,
		clientIPHeader: clientIPHeader,
	}

	if dex.clientIPHeader == "" {
		dex.clientIPHeader = "X-Forwarded-For"
	}

	return dex, nil
}

// UserInfo fetches the user's profile information using the provided OAuth2 token.
func (dex *Dex) UserInfo(ctx context.Context, tokenSource oauth2.TokenSource) (*oidc.UserInfo, error) {
	userInfo, err := dex.provider.UserInfo(ctx, tokenSource)
	if err != nil {
		return nil, err
	}
	return userInfo, err
}

// Health checks if the OAuth2/OIDC provider is healthy by calling its health endpoint.
func (dex *Dex) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dex.healthURL, nil)
	if err != nil {
		return err
	}
	res, err := dex.c.Do(req)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return ErrTimeout
		}
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return fmt.Errorf("%w: %v", ErrNetwork, urlErr.Err)
		}
		return err
	}
	defer res.Body.Close()
	// Expect 200
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status 200, got %d", res.StatusCode)
	}
	return nil
}
