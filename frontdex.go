// Package frontdex provides OAuth2/OIDC authentication middleware for applications using
// Dex as the identity provider and supports the authorization code flow.
package frontdex

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/tetsuo/frontdex/dex"
	"golang.org/x/oauth2"
)

// dexEndpoint sets the default Dex endpoint.
const dexEndpoint = "http://localhost:5556"

// Context keys.
const (
	payloadKey contextKey = "frontdex.Payload"
	errorKey   contextKey = "frontdex.Error"
	stateKey   contextKey = "frontdex.State"
	authURLKey contextKey = "frontdex.AuthURL"
)

// Dex related defaults.
const (
	// stateAge sets the default lifetime for state tokens.
	// Defaults to 24 hours as per Dex defaults (AuthRequestsValidFor).
	stateAge = 86400
	// tokenTTL sets the default ID token lifetime expected from Dex.
	// Defaults to 24 hours as per Dex defaults (IDTokensValidFor).
	tokenTTL = time.Hour * 24
	// clientRemoteIPHeader sets the default forwarded header.
	// Must match with the clientRemoteIP.header value set on Dex.
	clientRemoteIPHeader string = "X-Forwarded-For"
	// callbackPath sets the default OAuth2 callback path.
	// Must match with connector redirect URIs configured on Dex.
	callbackPath string = "/callback"
)

// Frontdex defaults.
const (
	// stateCookieName sets the default state token cookie name.
	stateCookieName string = "_fdx.state"
	// connectorFieldName sets the default query/form field name for the connector ID.
	connectorFieldName string = "via"
	// clientTimeout sets the default HTTP client timeout value for Dex requests.
	clientTimeout time.Duration = time.Second * 30
)

// State token structure.
// It contains state, nonce, and PKCE verifier.
const (
	verifierEnd = 172             // total length
	nonceEnd    = verifierEnd / 2 // 86
	stateEnd    = verifierEnd / 4 // 43
)

type options struct {
	// ErrorHandler overrides the default error handler.
	ErrorHandler http.Handler
	// RedirectHandler overrides the default redirect handler.
	RedirectHandler http.Handler
	// LoginHandler overrides the default login page handler.
	LoginHandler http.Handler
	// ConnectorFieldName specifies the form field name used to obtain the connector ID.
	ConnectorFieldName string
	// ClientRemoteIPHeader specifies the request header name used to get the user's IP address.
	// Defaults to "X-Forwarded-For".
	ClientRemoteIPHeader string
	// OAuth2Config is the OAuth2 client configuration for Dex.
	OAuth2Config *oauth2.Config
	// ProviderConfig is the OIDC provider configuration for Dex.
	ProviderConfig *oidc.ProviderConfig
	// CookieFactory is the factory for creating state token cookies.
	CookieFactory *cookieFactory
	// StateSecret sets the secret key for encrypting state tokens.
	StateSecret []byte
	// TrustedPeerCIDRs defines which IP ranges are allowed to send proxy headers.
	// If empty, proxy headers are never trusted.
	// Only requests from these IPs will have their "X-Forwarded-For" headers parsed.
	TrustedPeerCIDRs []netip.Prefix
	// TokenTTL specifies the auth token lifetime.
	// Should match with ID token lifetime on Dex. Defaults to 24h.
	TokenTTL time.Duration
	// Connectors is the list of available connectors configured on Dex.
	Connectors map[Connector]struct{}
	// ClientTimeout is the client timeout value for outgoing Dex requests.
	// Defaults to 30s.
	ClientTimeout time.Duration
	// Transport is the custom HTTP transport for outgoing Dex requests.
	Transport http.RoundTripper
}

// Crypto defines the interface for encrypting and decrypting state tokens.
type Crypto interface {
	// Decrypt decrypts the given data.
	Decrypt(data []byte) ([]byte, error)
	// Encrypt encrypts the given data.
	Encrypt(data []byte) ([]byte, error)
}

type frontdex struct {
	h    http.Handler
	cyp  Crypto
	opts *options
	dex  *dex.Dex
}

type contextKey string

// Connector represents a Dex connector ID.
type Connector = dex.Connector

// Errors.
var (
	// ErrNoState is returned when the OAuth2 state parameter is missing from the callback request.
	ErrNoState = errors.New("state missing")
	// ErrBadError is returned when an unrecognized error was returned in the OAuth2 callback.
	ErrBadError = errors.New("bad error")
	// ErrMissingStateToken is returned when the state token cookie is missing from the request.
	ErrMissingStateToken = errors.New("state token missing")
	// ErrBadStateToken is returned when the state token is invalid, tampered, or expired.
	ErrBadStateToken = errors.New("bad state token")
	// ErrAccessDenied is returned when the OAuth provider returns an "access_denied" or "unverified_user_email" error.
	// access_denied is standard, unverified_user_email is used by some providers like GitHub.
	ErrAccessDenied = errors.New("access denied")
	// ErrStateMismatch is returned when the state parameter in the callback doesn't match the initial state,
	// the value stored in the state token.
	ErrStateMismatch = errors.New("state mismatch")
)

// Errors returned from the Dex client.
var (
	// ErrBadConnector is returned when the connector field (via) in the request is invalid or not supported.
	ErrBadConnector = dex.ErrInvalidConnector
	// ErrResourceUnavailable is returned when a required resource (state) is not found on Dex.
	ErrResourceUnavailable = dex.ErrResourceUnavailable
	// ErrAuthFailure is returned when authentication failed at the Dex server.
	ErrAuthFailure = dex.ErrAuthFailure
	// ErrTimeout is returned when a request to Dex times out.
	ErrTimeout = dex.ErrTimeout
	// ErrNetwork is returned when a network error occurs while communicating with Dex.
	ErrNetwork = dex.ErrNetwork
)

// SameSiteMode represents the SameSite cookie attribute modes.
type SameSiteMode int

// SameSite options.
const (
	// SameSiteDefaultMode sets the 'SameSite' cookie attribute, which is
	// invalid in some older browsers due to changes in the SameSite spec. These
	// browsers will not send the cookie to the server.
	SameSiteDefaultMode SameSiteMode = iota + 1
	SameSiteLaxMode                  // default
	SameSiteStrictMode
	SameSiteNoneMode
)

type cookieFactory struct {
	Domain         string
	Path           string
	HttpOnly       bool
	Secure         bool
	SameSite       SameSiteMode
	CookieName     string
	TrustedOrigins []string
	MaxAge         int
}

func (cf *cookieFactory) newCookie(b []byte) *http.Cookie {
	return &http.Cookie{
		Name:     cf.CookieName,
		HttpOnly: cf.HttpOnly,
		Domain:   cf.Domain,
		Path:     cf.Path,
		SameSite: http.SameSite(cf.SameSite),
		Secure:   cf.Secure,
		Value:    base64.RawURLEncoding.EncodeToString(b),
		Expires:  time.Now().Add(time.Duration(cf.MaxAge) * time.Second),
	}
}

// New returns an [http.Handler] that provides OAuth2/OIDC authentication using Dex as
// the identity provider. It intercepts requests to / and /callback to handle the authorization
// and callback flows, respectively. All other requests are passed to the provided handler h.
// You should mount this handler under a dedicated path, such as /login/.
//
// The issuerURL, clientID, and clientSecret parameters configure the OAuth2 client and must match
// the values registered with your Dex server. Additional options, such as a custom Dex endpoint URL,
// can be provided using functional options.
//
// Note: set issuerURL to your application (for example, https://example.com/login), not to to Dex.
// Dex uses the issuer URL to validate redirect URIs, but its discovery document (/.well-known/openid-configuration)
// will advertise /keys, /token, and other endpoints under your application's URL. If your application
// tried to call those endpoints, it would end up calling itself.
// That's why frontdex does not use OIDC discovery; it constructs the required endpoints itself and
// talks directly to Dex (which must be reachable from the application server). By default, frontdex
// assumes Dex is at http://localhost:5556; if Dex runs elsewhere, use [WithEndpointURL] to set
// the correct Dex base URL.
//
// Upon successful authentication, the handler stores the authentication payload in the request context.
// You can retrieve it using the [Payload] function. The payload is only present in GET /callback requests
// after successful authentication.
//
// If authentication fails, the error is saved in the request context. Access it via [FailureReason] within
// the error handler; only requests routed to the [ErrorHandler] include this value.
// You can customize the handler with the [WithErrorHandler] option (recommended).
//
// Example usage:
//
//	import "github.com/tetsuo/frontdex"
//
//	fdx := frontdex.New(
//	  "https://example.com/login",             // issuer URL
//	  "example-client",                        // client ID
//	  "change-me-in-production",               // client secret
//	  frontdex.WithLoginHandler(loginHandler), // custom login page
//	)
//	http.ListenAndServe(":8080", http.StripPrefix("/login", fdx(
//	  http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//	    if payload := frontdex.Payload(r); payload != nil {
//	      w.Header().Set("Content-Type", "application/json")
//	      _ = json.NewEncoder(w).Encode(payload)
//	    }
//	  }),
//	)))
func New(issuerURL, clientID, clientSecret string, opts ...Option) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		fdx := parseOptions(h, issuerURL, opts...)

		fdx.opts.OAuth2Config.ClientID = clientID
		fdx.opts.OAuth2Config.ClientSecret = clientSecret

		provider := fdx.opts.ProviderConfig.NewProvider(context.Background())

		client, err := dex.NewDex(
			fdx.opts.Transport,            // custom HTTP transport for outgoing requests
			fdx.opts.OAuth2Config,         // oauth2 client configuration
			provider,                      // oidc provider instance
			fdx.opts.ClientRemoteIPHeader, // header name for client IP forwarding
			fdx.opts.ClientTimeout,        // timeout for outgoing requests
		)
		if err != nil {
			panic("frontdex: " + err.Error())
		}

		fdx.dex = client

		return fdx
	}
}

// ServeHTTP implements the http.Handler interface.
func (fdx *frontdex) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		switch r.URL.Path {
		case "", "/":
			if url, token, err := fdx.handleRedirect(r); err == nil {
				r = contextSave(r, authURLKey, url)
				r = contextSave(r, stateKey, fdx.opts.CookieFactory.newCookie(token))
				fdx.opts.RedirectHandler.ServeHTTP(w, r)
			} else {
				r = contextSave(r, errorKey, err)
				fdx.opts.ErrorHandler.ServeHTTP(w, r)
			}
			return
		}
	case http.MethodGet:
		switch r.URL.Path {
		case "", "/":
			fdx.opts.LoginHandler.ServeHTTP(w, r)
			return
		case callbackPath:
			if payload, err := fdx.handleCallback(r); err == nil {
				r = contextSave(r, payloadKey, payload)
			} else {
				r = contextSave(r, errorKey, err)
				fdx.opts.ErrorHandler.ServeHTTP(w, r)
				return
			}
		}
	}

	fdx.h.ServeHTTP(w, r)
}

func (fdx *frontdex) clientIP(r *http.Request) string {
	remoteAddr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}

	remoteIP, err := netip.ParseAddr(remoteAddr)
	if err != nil {
		return ""
	}

	// Check if the request comes from a trusted peer
	for _, n := range fdx.opts.TrustedPeerCIDRs {
		if !n.Contains(remoteIP) {
			return remoteAddr // Fallback to the address from the request if the header is provided
		}
	}

	// Try to get a single IP from X-Forwarded-For header; if multiple comma-separated IPs are
	// present, this won't parse it. In that case, we fallback to the remote address.
	ipVal := r.Header.Get("X-Forwarded-For")
	if ipVal != "" {
		ip, err := netip.ParseAddr(ipVal)
		if err == nil {
			return ip.String()
		}
	}

	return remoteAddr
}

func contextGet[A any](r *http.Request, key contextKey) (a A) {
	if v := r.Context().Value(key); v != nil {
		return v.(A)
	}
	return
}

func contextSave[A any](r *http.Request, key contextKey, val A) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), key, val))
}

// FailureReason retrieves the error value from the request context.
// This value is only present in error handler.
func FailureReason(r *http.Request) error {
	return contextGet[error](r, errorKey)
}

// StateToken retrieves the state token cookie from the request context.
// This value is only present in redirect handler.
func StateToken(r *http.Request) *http.Cookie {
	return contextGet[*http.Cookie](r, stateKey)
}

// AuthorizationURL retrieves the OAuth2 authorization URL from the request context.
// This value is only present in redirect handler.
func AuthorizationURL(r *http.Request) string {
	return contextGet[string](r, authURLKey)
}

// Payload retrieves the authentication payload from the request context.
// This value is only present after successful authentication.
func Payload(r *http.Request) *dex.Payload {
	return contextGet[*dex.Payload](r, payloadKey)
}

// StatusCodeFromError maps known authentication and API errors to appropriate HTTP status codes
// for use in HTTP responses. Returns 400, 403, or 500 depending on the error type.
func StatusCodeFromError(err error) int {
	switch err {
	case ErrNoState, ErrBadError, ErrMissingStateToken, ErrBadStateToken:
		return http.StatusBadRequest
	case ErrAccessDenied, ErrStateMismatch:
		return http.StatusForbidden
	case ErrTimeout:
		return http.StatusGatewayTimeout
	}
	// Handle wrapped API errors
	if errors.Is(err, ErrResourceUnavailable) ||
		errors.Is(err, ErrBadConnector) {
		return http.StatusBadRequest
	}
	if errors.Is(err, ErrAuthFailure) {
		return http.StatusForbidden
	}
	return http.StatusInternalServerError
}

// Default request handlers.
var (
	// ErrorHandler sends an appropriate HTTP error response based on the failure reason.
	// Used when an error occurs during the authentication process. Override with [WithErrorHandler].
	ErrorHandler = http.HandlerFunc(errorHandler)

	// RedirectHandler sets the state token cookie and redirects to the authorization URL.
	// Used to initiate the authentication process. Override with [WithRedirectHandler].
	RedirectHandler = http.HandlerFunc(redirectHandler)
)

func errorHandler(w http.ResponseWriter, r *http.Request) {
	err := FailureReason(r)
	http.Error(w, err.Error(), StatusCodeFromError(err))
}

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	// Set the state token cookie
	http.SetCookie(w, StateToken(r))
	// Redirect to the authorization URL
	http.Redirect(w, r, AuthorizationURL(r), http.StatusFound)
}
