package frontdex

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/tetsuo/frontdex/dex"
	"github.com/tetsuo/frontdex/internal/crypto"
	"github.com/tetsuo/realip"
	"golang.org/x/oauth2"
)

// Option configures a frontdex instance.
type Option func(*frontdex)

// Dex/OIDC options.

// WithEndpointURL sets the base URL for the Dex server and configures the OAuth2 endpoints
// (auth, token), JWKS (keys), and userinfo URLs accordingly. Note that frontdex doesn't use
// the discovery protocol to obtain these URLs.
// Defaults to the development endpoint (http://localhost:5556).
func WithEndpointURL(endpoint string) Option {
	return func(fdx *frontdex) {
		fdx.opts.OAuth2Config.Endpoint = oauth2.Endpoint{
			TokenURL: endpoint + "/token",
			AuthURL:  endpoint + "/auth",
		}
		fdx.opts.ProviderConfig.JWKSURL = endpoint + "/keys"
		fdx.opts.ProviderConfig.UserInfoURL = endpoint + "/userinfo"
	}
}

// WithOAuthRedirectURL sets the OAuth2 redirect URL used for callbacks.
// Must match with connector redirect URI configuration in Dex.
// Defaults to issuerURL + "/callback".
func WithOAuthRedirectURL(redirectURL string) Option {
	return func(fdx *frontdex) {
		fdx.opts.OAuth2Config.RedirectURL = redirectURL
	}
}

// WithOAuthScopes sets the OAuth scopes requested from Dex during login.
// Default: openid, profile, email, federated:id.
func WithOAuthScopes(scopes []string) Option {
	return func(fdx *frontdex) {
		fdx.opts.OAuth2Config.Scopes = scopes
	}
}

// WithTokenTTL configures the expected lifetime of the ID token issued by Dex.
// Used for validation. Must match Dex's expiry.idToken. Defaults to 24h.
func WithTokenTTL(d time.Duration) Option {
	return func(fdx *frontdex) {
		fdx.opts.TokenTTL = d
	}
}

// WithClientRemoteIPHeader sets the name of the header sent to Dex containing
// the client's IP address.
// This must match the clientRemoteIP.header value in the Dex configuration.
// Defaults to "X-Forwarded-For".
func WithClientRemoteIPHeader(headerName string) Option {
	return func(fdx *frontdex) {
		fdx.opts.ClientRemoteIPHeader = headerName
	}
}

// WithConnectors restricts authentication to the specified Dex connector IDs.
// Only these connectors will be allowed when sending requests to Dex.
func WithConnectors(connectors []string) Option {
	return func(fdx *frontdex) {
		for _, v := range connectors {
			fdx.opts.Connectors[Connector(v)] = struct{}{}
		}
	}
}

// Cookie options.

// WithCookieName sets the name of the cookie provided to clients
// as part of the OAuth2 authentication flow. Cookie names must not contain whitespace,
// commas, semicolons, backslashes, or control characters, as per RFC 6265.
// Default value is "_fdx_chal".
func WithCookieName(name string) Option {
	return func(fdx *frontdex) {
		fdx.opts.CookieFactory.CookieName = name
	}
}

// WithCookieMaxAge sets the maximum age (in seconds) for cookies provided to clients
// as part of the OAuth2 authentication flow.
// Must match Dex's expiry.authRequests. Defaults to 24h.
func WithCookieMaxAge(age int) Option {
	return func(fdx *frontdex) {
		fdx.opts.CookieFactory.MaxAge = age
	}
}

// WithCookieDomain sets the domain attribute for cookies provided to clients during
// the OAuth2 authentication flow.
// Defaults to the current request domain (recommended).
// The value is treated as being prefixed with a '.', so "example.com" also
// matches subdomains like "www.example.com".
func WithCookieDomain(domain string) Option {
	return func(fdx *frontdex) {
		fdx.opts.CookieFactory.Domain = domain
	}
}

// WithCookiePath sets the path for cookies provided to clients during
// the OAuth2 authentication flow.
// Defaults to the path the cookie was issued from (recommended).
func WithCookiePath(path string) Option {
	return func(fdx *frontdex) {
		fdx.opts.CookieFactory.Path = path
	}
}

// WithCookieSecure toggles the 'Secure' flag on cookies provided to clients
// during the OAuth2 authentication flow.
// Defaults to true; disable only for local HTTP development.
func WithCookieSecure(secure bool) Option {
	return func(fdx *frontdex) {
		fdx.opts.CookieFactory.Secure = secure
	}
}

// WithCookieHttpOnly toggles the 'HttpOnly' flag on cookies provided to clients
// during the OAuth2 authentication flow.
// Defaults to true.
func WithCookieHttpOnly(httpOnly bool) Option {
	return func(fdx *frontdex) {
		fdx.opts.CookieFactory.HttpOnly = httpOnly
	}
}

// WithCookieSameSite sets the 'SameSite' attribute for cookies provided to clients
// during the OAuth2 authentication flow.
// Defaults to [SameSiteLaxMode].
func WithCookieSameSite(sameSite SameSiteMode) Option {
	return func(fdx *frontdex) {
		fdx.opts.CookieFactory.SameSite = sameSite
	}
}

// WithCookieTrustedOrigins registers Referer origins that are treated as trusted
// when handling cookies during the OAuth2 authentication flow.
// Only include origins you own or fully control.
func WithCookieTrustedOrigins(origins []string) Option {
	return func(fdx *frontdex) {
		fdx.opts.CookieFactory.TrustedOrigins = origins
	}
}

// WithStateSecret specifies the key used by the built-in AES cipher to encrypt and decrypt
// state token values. The key must be 16, 24, or 32 bytes long; if not set, a random 32-byte key
// is used by default.
func WithStateSecret(key []byte) Option {
	return func(fdx *frontdex) {
		if key == nil {
			return
		}
		fdx.opts.StateSecret = key
	}
}

// WithStateSecretHex sets the state secret key using a hex-encoded string.
// The decoded key must be exactly 16, 24, or 32 bytes in length.
func WithStateSecretHex(hexKey string) Option {
	return func(fdx *frontdex) {
		if hexKey == "" {
			return
		}
		b, err := hex.DecodeString(hexKey)
		if err != nil {
			return
		}
		WithStateSecret(b)(fdx)
	}
}

// WithCustomCrypto injects a custom [Crypto] implementation for encrypting and decrypting
// state token values. By default AES is used with a random 32-byte key.
// Setting a custom [Crypto] overrides any state secret set via [WithStateSecret]
// or [WithStateSecretHex].
func WithCustomCrypto(cyp Crypto) Option {
	return func(fdx *frontdex) {
		fdx.cyp = cyp
	}
}

// Forwarded header options.

// WithRealIPHeaders sets the list of headers to inspect when determining the client IP address
// to send to Dex (using the header specified with [WithClientRemoteIPHeader]).
// By default, frontdex ignores forwarded headers from untrusted sources. For security, ensure
// only trusted peers or proxies can set these headers using [WithRealIPTrustedProxies], [WithRealIPTrustedPeers],
// or [WithRealIPProxyHopCount]. The default is ["X-Forwarded-For"].
func WithRealIPHeaders(headers []string) Option {
	return func(fdx *frontdex) {
		opt := realip.WithHeaders(headers)
		opt(fdx.opts.RealIP)
	}
}

// WithRealIPTrustedProxies sets trusted proxy IP prefixes used for determining the client IP address.
// This defines which IP ranges are allowed to set forwarding headers.
// When set, forwarded headers are only checked if the request comes from a trusted peer.
// Otherwise, the remote address is returned.
func WithRealIPTrustedProxies(proxies []netip.Prefix) Option {
	return func(fdx *frontdex) {
		opt := realip.WithTrustedProxies(proxies)
		opt(fdx.opts.RealIP)
	}
}

// WithRealIPTrustedPeers sets trusted peer IP prefixes used for determining the client IP address.
// Use it to specify IP ranges of internal proxies that should be skipped when parsing
// the forwarding chain.
func WithRealIPTrustedPeers(peers []netip.Prefix) Option {
	return func(fdx *frontdex) {
		opt := realip.WithTrustedPeers(peers)
		opt(fdx.opts.RealIP)
	}
}

// WithRealIPProxyHopCount sets how many proxy hops to trust when determining the client IP address.
// Sets the exact number of proxy hops to skip from the end of the forwarding chain.
// If you know there are exactly N proxies in your chain, use this setting to skip them.
func WithRealIPProxyHopCount(cnt int) Option {
	return func(fdx *frontdex) {
		opt := realip.WithProxyCnt(cnt)
		opt(fdx.opts.RealIP)
	}
}

// Handler options.

// WithErrorHandler overrides the default error handler for OAuth callbacks.
// By default, a simple text error response is returned.
// Note that internal server errors (500) might contain sensitive information. It's recommended
// to log such errors instead of displaying them to users.
//
// For production use, consider implementing a custom error handler. For example:
//
//	WithErrorHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//	    err := frontdex.FailureReason(r)
//	    statusCode := frontdex.StatusCodeFromError(err)
//	    if statusCode == http.StatusInternalServerError {
//	        // Log the error details internally
//	        log.Printf("Internal error: %v (status: %d)", err, statusCode)
//	        // Return a generic error message to the user
//	        http.Error(w, "Something went wrong", statusCode)
//	    } else {
//	        http.Error(w, err.Error(), statusCode)
//	    }
//	}))
func WithErrorHandler(h http.Handler) Option {
	return func(fdx *frontdex) {
		fdx.opts.ErrorHandler = h
	}
}

// WithRedirectHandler overrides the default redirect handler.
// By default, the handler sets the state token cookie and redirects to the authorization URL.
// For custom behavior, implement your own handler.
//
// You can access the state token and authorization URL using [StateToken] and [AuthorizationURL].
// The default handler logic is as follows:
//
//	WithRedirectHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//	    // Set the state token cookie
//	    http.SetCookie(w, frontdex.StateToken(r))
//
//	    // Redirect to the authorization URL
//	    http.Redirect(w, r, frontdex.AuthorizationURL(r), http.StatusFound)
//	}))
//
// For example, add CSRF protection:
//
//	import "github.com/gorilla/csrf"
//
//	protect := csrf.Protect(...)
//
//	opts := []frontdex.Option{
//	    frontdex.WithRedirectHandler(protect(frontdex.RedirectHandler)),
//	    frontdex.WithLoginHandler(protect(yourLoginHandler)),
//	}
func WithRedirectHandler(h http.Handler) Option {
	return func(fdx *frontdex) {
		fdx.opts.RedirectHandler = h
	}
}

// WithLoginHandler overrides the default login page handler.
// By default, a simple HTML page with buttons for each available connector is served.
func WithLoginHandler(h http.Handler) Option {
	return func(fdx *frontdex) {
		fdx.opts.LoginHandler = h
	}
}

// Frontdex specific options.

// WithHTTPClientTimeout sets the timeout duration for requests sent to Dex.
// Defaults to 30s.
func WithHTTPClientTimeout(timeout time.Duration) Option {
	return func(fdx *frontdex) {
		fdx.opts.ClientTimeout = timeout
	}
}

// WithCustomTransport sets the custom HTTP transport for requests sent to Dex.
func WithCustomTransport(rt http.RoundTripper) Option {
	return func(fdx *frontdex) {
		fdx.opts.Transport = rt
	}
}

// WithConnectorFieldName sets the form field name used to obtain the connector ID.
// Defaults to "via".
func WithConnectorFieldName(name string) Option {
	return func(fdx *frontdex) {
		fdx.opts.ConnectorFieldName = name
	}
}

// parseOptions parses the supplied options functions and returns a configured frontdex.
func parseOptions(h http.Handler, issuer string, opts ...Option) *frontdex {
	issuerURL, err := url.Parse(issuer)
	if err != nil {
		panic("frontdex: " + err.Error())
	}

	issuerURL = &url.URL{
		Scheme: issuerURL.Scheme,
		Host:   issuerURL.Host,
		Path:   issuerURL.Path,
	}

	fdx := &frontdex{h: h}

	// Apply initial defaults before user options.
	applyDefaults(issuerURL, fdx)

	// Options functions are applied in order, with any conflicting options
	// overriding earlier calls.
	for _, option := range opts {
		option(fdx)
	}

	// Ensure defaults if unset or zeroed by user input.
	ensureDefaults(issuerURL, fdx)

	return fdx
}

// applyDefaults sets initial default values before user options are applied.
func applyDefaults(issuerURL *url.URL, fdx *frontdex) {
	fdx.opts = &options{
		OAuth2Config: &oauth2.Config{},
		ProviderConfig: &oidc.ProviderConfig{
			IssuerURL: issuerURL.String(),
		},
		CookieFactory: &cookieFactory{
			Secure:   true,
			HttpOnly: true,
			SameSite: SameSiteLaxMode,
		},
		RealIP: realip.New(
			// Default xff header is "X-Forwarded-For"
			realip.WithHeaders([]string{realip.XForwardedFor}),
		),
		Connectors:    make(map[Connector]struct{}),
		Transport:     http.DefaultTransport,
		ClientTimeout: clientTimeout,
	}
}

// ensureDefaults is called after all options have been applied.
func ensureDefaults(issuerURL *url.URL, fdx *frontdex) {
	// JWKSURL is empty if the Dex endpoint is not set; set it to localhost.
	if fdx.opts.ProviderConfig.JWKSURL == "" {
		WithEndpointURL(dexEndpoint + issuerURL.Path)(fdx)
	}

	// Default scopes
	if len(fdx.opts.OAuth2Config.Scopes) == 0 {
		WithOAuthScopes([]string{oidc.ScopeOpenID, "profile", "email", "federated:id"})(fdx)
	}

	// Use the issuerURL and the callback path to construct the redirect URL if unset.
	if fdx.opts.OAuth2Config.RedirectURL == "" {
		redirectURL := &url.URL{
			Scheme: issuerURL.Scheme,
			Host:   issuerURL.Host,
			Path:   path.Join(issuerURL.Path, callbackPath[1:]),
		}
		WithOAuthRedirectURL(redirectURL.String())(fdx)
	}

	// Default lifetimes: both are 24h as per Dex defaults
	if fdx.opts.TokenTTL <= 0 {
		fdx.opts.TokenTTL = tokenTTL
	}

	if fdx.opts.CookieFactory.MaxAge <= 0 {
		fdx.opts.CookieFactory.MaxAge = stateAge
	}

	// Default cookie name
	if fdx.opts.CookieFactory.CookieName == "" {
		fdx.opts.CookieFactory.CookieName = stateCookieName
	}

	if fdx.opts.ConnectorFieldName == "" {
		fdx.opts.ConnectorFieldName = connectorFieldName
	}

	if fdx.opts.ClientRemoteIPHeader == "" {
		fdx.opts.ClientRemoteIPHeader = clientRemoteIPHeader // X-Forwarded-For
	}

	// Set default transport if the default was removed.
	if fdx.opts.Transport == nil {
		WithCustomTransport(http.DefaultTransport)(fdx)
	}

	// Enable all connectors when available connectors not set.
	if len(fdx.opts.Connectors) == 0 {
		fdx.opts.Connectors = map[Connector]struct{}{
			dex.ConnectorAtlassianCrowd: {},
			dex.ConnectorAuthProxy:      {},
			dex.ConnectorBitbucketCloud: {},
			dex.ConnectorGitea:          {},
			dex.ConnectorGitHub:         {},
			dex.ConnectorGitLab:         {},
			dex.ConnectorGoogle:         {},
			dex.ConnectorKeystone:       {},
			dex.ConnectorLDAP:           {},
			dex.ConnectorLinkedIn:       {},
			dex.ConnectorMicrosoft:      {},
			dex.ConnectorMock:           {},
			dex.ConnectorOAuth:          {},
			dex.ConnectorOpenIDConnect:  {},
			dex.ConnectorOpenShift:      {},
			dex.ConnectorSAML:           {},
		}
	}

	// Set the default Crypto if none set.
	if fdx.cyp == nil {
		k := fdx.opts.StateSecret
		if k == nil {
			// Generate a random 32-byte key if no secret provided.
			k = make([]byte, 32)
			_, err := rand.Read(k)
			if err != nil {
				panic("frontdex: " + err.Error())
			}
		}
		cyp, err := crypto.NewAESCipher(k)
		if err != nil {
			// Note that this will panic if the provided key length is invalid.
			panic("frontdex: " + err.Error())
		}
		fdx.cyp = cyp
	}

	// Default handlers.

	if fdx.opts.ErrorHandler == nil {
		fdx.opts.ErrorHandler = ErrorHandler
	}

	if fdx.opts.RedirectHandler == nil {
		fdx.opts.RedirectHandler = RedirectHandler
	}

	// The default login page for development.
	if fdx.opts.LoginHandler == nil {
		var htmlStr strings.Builder
		htmlStr.WriteString(`<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>frontdex</title>
  </head>
  <body>
    <form method="POST">`)
		for connector := range fdx.opts.Connectors {
			fmt.Fprintf(&htmlStr, `<button type="submit" name="via" value="%s">%s</button>`, connector, connector)
		}
		fdx.opts.LoginHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, htmlStr.String())
		})
		fmt.Fprintf(&htmlStr, `</form>
  </body>
</html>`)
	}
}
