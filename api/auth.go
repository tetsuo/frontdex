package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"golang.org/x/net/html"
	"golang.org/x/oauth2"
)

// AuthRequest contains parameters for building an OAuth2 authorization request to Dex.
type AuthRequest struct {
	State               string    // CSRF protection and session tracking
	Nonce               string    // Prevents replay attacks
	CodeChallenge       string    // PKCE challenge value
	CodeChallengeMethod string    // PKCE challenge method (usually S256)
	ClientIP            string    // Client IP address
	Via                 Connector // Which connector to use (e.g., google, github)
}

// GetAuthorizationURL builds and sends an authorization request to the OAuth provider,
// returning the redirect URL for user login or an error if the request fails.
func (dex *Dex) GetAuthorizationURL(ctx context.Context, params *AuthRequest) (string, error) {
	opts := make([]oauth2.AuthCodeOption, 0, 4)
	if params.Via != "" {
		opts = append(opts, oauth2.SetAuthURLParam("connector_id", string(params.Via)))
	}
	if params.Nonce != "" {
		opts = append(opts, oauth2.SetAuthURLParam("nonce", params.Nonce))
	}
	if params.CodeChallenge != "" {
		codeChallengeMethod := params.CodeChallengeMethod
		if codeChallengeMethod == "" {
			params.CodeChallengeMethod = "S256"
		}
		opts = append(opts,
			oauth2.SetAuthURLParam("code_challenge", params.CodeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", params.CodeChallengeMethod))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		dex.oauth2cfg.AuthCodeURL(params.State, opts...), nil)
	if err != nil {
		return "", err
	}

	if params.ClientIP != "" {
		req.Header.Set(dex.clientIPHeader, params.ClientIP)
	}

	res, err := dex.c.Do(req)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "", ErrTimeout
		}
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return "", fmt.Errorf("%w: %v", ErrNetwork, urlErr.Err)
		}
		return "", err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	// Expect 302 Found for successful flow
	case http.StatusFound:
		locationURL := res.Header.Get("Location")
		if locationURL == "" {
			return "", fmt.Errorf("missing Location header in dex 302 response")
		}
		return locationURL, nil
	case http.StatusNotFound, http.StatusBadRequest, http.StatusInternalServerError:
		n, err := html.Parse(res.Body)
		if err != nil {
			return "", fmt.Errorf("failed to parse dex %d error response: %v", res.StatusCode, err)
		}
		if err = parseErrorFromHTML(n); err == nil {
			return "", fmt.Errorf("dex returned %d, but no error information found in HTML", res.StatusCode)
		} else {
			return "", err
		}
	case http.StatusSeeOther:
		// Handle 303 See Other with error in callback URL
		locationURL := res.Header.Get("Location")
		if locationURL == "" {
			return "", fmt.Errorf("missing Location header in dex 303 error response")
		}
		if err := parseErrorFromLocation(locationURL); err == nil {
			return "", fmt.Errorf("dex returned 303 but no error information found in Location")
		} else {
			return "", err
		}
	}

	return "", fmt.Errorf("dex returned unexpected status code: %d", res.StatusCode)
}
