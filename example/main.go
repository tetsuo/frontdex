package main

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/csrf"
	"github.com/tetsuo/frontdex"
	"github.com/tetsuo/hartransport"
)

//go:embed login.html
var loginHTML string

func main() {
	// Dex/OIDC client configuration (required).
	var (
		issuerURL    = "http://localhost:8080/login"
		clientID     = "example-client"
		clientSecret = "change-me-in-production"
	)

	// Parse the login HTML template
	tmpl, err := template.New("login").Parse(loginHTML)
	if err != nil {
		log.Fatalf("template parse: %v", err)
	}

	csrfProtect := csrf.Protect(
		[]byte("32-byte-long-auth-key"),
		csrf.Secure(false),
		csrf.TrustedOrigins([]string{"localhost:8080"}),
	)

	// Create a HAR transport to log HTTP requests/responses to "log.har".
	har, err := hartransport.NewHARTransport(http.DefaultTransport, "log.har")
	if err != nil {
		log.Fatalf("hartransport: %v", err)
	}

	opts := []frontdex.Option{
		frontdex.WithCookieSecure(false),  // for localhost testing over HTTP
		frontdex.WithCustomTransport(har), // for logging HTTP requests/responses
		frontdex.WithCookiePath("/login"), // restrict cookies to /login path
		frontdex.WithCookieName("_loginstate"),
		frontdex.WithConnectors([]string{
			"github", "mock", "google",
		}), // limit to specific connectors
		frontdex.WithConnectorFieldName("connector"), // custom form field name for connector ID
		frontdex.WithLoginHandler(csrfProtect(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				if err := tmpl.Execute(w, map[string]template.HTML{
					"Title":          "frontdex",
					csrf.TemplateTag: csrf.TemplateField(r),
				}); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
			}),
		)), // custom login page with CSRF protection
		frontdex.WithRedirectHandler(csrfProtect(frontdex.RedirectHandler)), // protect redirect handler with CSRF
		frontdex.WithErrorHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			err := frontdex.FailureReason(r)
			statusCode := frontdex.StatusCodeFromError(err)
			if statusCode == http.StatusInternalServerError {
				// Log the error details internally
				log.Printf("Internal error: %v (status: %d)", err, statusCode)
				// Return a generic error message to the user
				http.Error(w, "Something went wrong", statusCode)
			} else {
				http.Error(w, err.Error(), statusCode)
			}
		})), // custom error handler
		frontdex.WithStateSecretHex("7f9c2ba4e88f827d616045507605853ed73b8093c2af1f4b3f1b2c1f3f8e3b2b"), // custom state secret
	}

	fdx := frontdex.New(issuerURL, clientID, clientSecret, opts...)

	handler := fdx(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// frontdex falls through to this handler after successful login.
			// We only want to handle the callback path here.
			if r.URL.Path != "/callback" {
				http.NotFound(w, r)
				return
			}
			// Only allow GET requests
			if r.Method != http.MethodGet {
				http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
				return
			}

			// User is logged in; use the JWT payload
			payload := frontdex.Payload(r)

			// Example: enforce email verification
			if !payload.Claims.EmailVerified {
				http.Error(w, "email not verified", http.StatusForbidden)
				return
			}

			// Dump the payload as JSON
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(payload)
		}),
	)

	addr := "localhost:8080"

	if err := http.ListenAndServe(addr, http.StripPrefix("/login", handler)); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
