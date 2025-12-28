package frontdex_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tetsuo/frontdex"
)

// Test helper functions

func mockSuccessfulDexAuthRedirect() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Simulate Dex redirect to external provider
		externalAuthURL := url.URL{
			Scheme: "https",
			Host:   "example-provider.com",
			Path:   "/oauth/authorize",
		}
		query := r.URL.Query()
		q := externalAuthURL.Query()
		q.Set("client_id", "test-client-id")
		q.Set("redirect_uri", query.Get("redirect_uri"))
		q.Set("response_type", "code")
		q.Set("state", query.Get("state"))
		q.Set("nonce", query.Get("nonce"))
		// Pass through PKCE parameters
		if codeChallenge := query.Get("code_challenge"); codeChallenge != "" {
			q.Set("code_challenge", codeChallenge)
		}
		if codeChallengeMethod := query.Get("code_challenge_method"); codeChallengeMethod != "" {
			q.Set("code_challenge_method", codeChallengeMethod)
		}
		externalAuthURL.RawQuery = q.Encode()

		w.Header().Set("Location", externalAuthURL.String())
		w.WriteHeader(http.StatusFound)
	}
}

// Tests for the redirect flow

func TestRedirectGitHubConnector(t *testing.T) {
	mockDexServer := httptest.NewServer(mockSuccessfulDexAuthRedirect())
	defer mockDexServer.Close()

	issuerURL := mockDexServer.URL + "/login"
	clientID := "test-client-id"
	clientSecret := "test-client-secret"

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Success"))
	})

	fdx := frontdex.New(
		issuerURL,
		clientID,
		clientSecret,
		frontdex.WithEndpointURL(mockDexServer.URL),
		frontdex.WithConnectors([]string{"github", "google"}),
		frontdex.WithCookieSecure(false),
	)(handler)

	// Create a POST request to initiate redirect
	form := url.Values{}
	form.Set("via", "github")
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	fdx.ServeHTTP(rec, req)

	// Should get a redirect response
	if rec.Code != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, rec.Code)
	}

	// Check that Location header is set
	location := rec.Header().Get("Location")
	if location == "" {
		t.Fatal("expected Location header to be set")
	}

	// Parse the redirect URL
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse redirect URL: %v", err)
	}

	// Verify query parameters
	query := redirectURL.Query()
	if query.Get("state") == "" {
		t.Error("expected state parameter in redirect URL")
	}
	if query.Get("code_challenge") == "" {
		t.Error("expected code_challenge parameter in redirect URL")
	}
	if query.Get("code_challenge_method") != "S256" {
		t.Errorf("expected code_challenge_method S256, got %s", query.Get("code_challenge_method"))
	}

	// Verify cookie was set
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected cookie to be set")
	}

	var stateCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "_fdx.state" {
			stateCookie = cookie
			break
		}
	}

	if stateCookie == nil {
		t.Fatal("expected state cookie to be set")
	}

	if stateCookie.Value == "" {
		t.Error("expected non-empty state cookie value")
	}
}

func TestRedirectInvalidOrMissingConnector(t *testing.T) {
	mockDexServer := httptest.NewServer(mockSuccessfulDexAuthRedirect())
	defer mockDexServer.Close()

	issuerURL := mockDexServer.URL + "/login"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name         string
		form         url.Values
		expectedBody string
	}{
		{
			name:         "invalid connector",
			form:         url.Values{"via": {"invalid-connector"}},
			expectedBody: "connector invalid\n",
		},
		{
			name:         "missing connector",
			form:         nil,
			expectedBody: "connector invalid\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fdx := frontdex.New(
				issuerURL,
				"test-client-id",
				"test-client-secret",
				frontdex.WithEndpointURL(mockDexServer.URL),
				frontdex.WithConnectors([]string{"github", "google"}),
				frontdex.WithCookieSecure(false),
			)(handler)

			var req *http.Request
			if tt.form != nil {
				req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tt.form.Encode()))
			} else {
				req = httptest.NewRequest(http.MethodPost, "/", nil)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rec := httptest.NewRecorder()
			fdx.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
			}

			if rec.Body.String() != tt.expectedBody {
				t.Errorf("expected %q, got: %q", tt.expectedBody, rec.Body.String())
			}
		})
	}
}

func TestRedirectCustomConnectorFieldName(t *testing.T) {
	mockDexServer := httptest.NewServer(mockSuccessfulDexAuthRedirect())
	defer mockDexServer.Close()

	issuerURL := mockDexServer.URL + "/login"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	fdx := frontdex.New(
		issuerURL,
		"test-client-id",
		"test-client-secret",
		frontdex.WithEndpointURL(mockDexServer.URL),
		frontdex.WithConnectors([]string{"github"}),
		frontdex.WithConnectorFieldName("connector"),
		frontdex.WithCookieSecure(false),
	)(handler)

	// Create a POST request with custom field name
	form := url.Values{}
	form.Set("connector", "github")
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	fdx.ServeHTTP(rec, req)

	// Should get a redirect response
	if rec.Code != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, rec.Code)
	}

	location := rec.Header().Get("Location")
	if location == "" {
		t.Error("expected Location header to be set")
	}
}

func TestRedirectMultipleConnectors(t *testing.T) {
	connectors := []string{"github", "google", "mock"}

	for _, connector := range connectors {
		t.Run(connector, func(t *testing.T) {
			mockDexServer := httptest.NewServer(mockSuccessfulDexAuthRedirect())
			defer mockDexServer.Close()

			issuerURL := mockDexServer.URL + "/login"
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			fdx := frontdex.New(
				issuerURL,
				"test-client-id",
				"test-client-secret",
				frontdex.WithEndpointURL(mockDexServer.URL),
				frontdex.WithConnectors(connectors),
				frontdex.WithCookieSecure(false),
			)(handler)

			form := url.Values{}
			form.Set("via", connector)
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rec := httptest.NewRecorder()
			fdx.ServeHTTP(rec, req)

			if rec.Code != http.StatusFound {
				t.Errorf("expected status %d for %s, got %d", http.StatusFound, connector, rec.Code)
			}

			location := rec.Header().Get("Location")
			if location == "" {
				t.Errorf("expected Location header for %s", connector)
			}
		})
	}
}

func TestRedirectTimeout(t *testing.T) {
	// Create a server that delays response
	mockDexServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		mockSuccessfulDexAuthRedirect()(w, r)
	}))
	defer mockDexServer.Close()

	issuerURL := mockDexServer.URL + "/login"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	fdx := frontdex.New(
		issuerURL,
		"test-client-id",
		"test-client-secret",
		frontdex.WithEndpointURL(mockDexServer.URL),
		frontdex.WithConnectors([]string{"github"}),
		frontdex.WithHTTPClientTimeout(100*time.Millisecond),
		frontdex.WithCookieSecure(false),
	)(handler)

	form := url.Values{}
	form.Set("via", "github")
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	fdx.ServeHTTP(rec, req)

	if rec.Code != http.StatusGatewayTimeout {
		t.Errorf("expected status %d, got %d", http.StatusGatewayTimeout, rec.Code)
	}

	if rec.Body.String() != "timeout\n" {
		t.Errorf("expected timeout error message, got: %q", rec.Body.String())
	}
}

func TestRedirectCustomCookieName(t *testing.T) {
	mockDexServer := httptest.NewServer(mockSuccessfulDexAuthRedirect())
	defer mockDexServer.Close()

	issuerURL := mockDexServer.URL + "/login"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	customCookieName := "_custom_state_cookie"

	fdx := frontdex.New(
		issuerURL,
		"test-client-id",
		"test-client-secret",
		frontdex.WithEndpointURL(mockDexServer.URL),
		frontdex.WithConnectors([]string{"github"}),
		frontdex.WithCookieName(customCookieName),
		frontdex.WithCookieSecure(false),
	)(handler)

	form := url.Values{}
	form.Set("via", "github")
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	fdx.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, rec.Code)
	}

	// Verify custom cookie name was used
	cookies := rec.Result().Cookies()
	var foundCookie bool
	for _, cookie := range cookies {
		if cookie.Name == customCookieName {
			foundCookie = true
			break
		}
	}

	if !foundCookie {
		t.Errorf("expected cookie with name %q, but it was not set", customCookieName)
	}
}

func TestRedirectCustomErrorHandler(t *testing.T) {
	mockDexServer := httptest.NewServer(mockSuccessfulDexAuthRedirect())
	defer mockDexServer.Close()

	issuerURL := mockDexServer.URL + "/login"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	customErrorHandlerCalled := false
	customErrorHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		customErrorHandlerCalled = true
		err := frontdex.FailureReason(r)
		w.WriteHeader(http.StatusTeapot)
		w.Write([]byte("Custom error: " + err.Error()))
	})

	fdx := frontdex.New(
		issuerURL,
		"test-client-id",
		"test-client-secret",
		frontdex.WithEndpointURL(mockDexServer.URL),
		frontdex.WithConnectors([]string{"github"}),
		frontdex.WithErrorHandler(customErrorHandler),
		frontdex.WithCookieSecure(false),
	)(handler)

	// Send request with invalid connector to trigger error
	form := url.Values{}
	form.Set("via", "invalid")
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	fdx.ServeHTTP(rec, req)

	if !customErrorHandlerCalled {
		t.Error("expected custom error handler to be called")
	}

	if rec.Code != http.StatusTeapot {
		t.Errorf("expected status %d, got %d", http.StatusTeapot, rec.Code)
	}

	if !strings.Contains(rec.Body.String(), "Custom error") {
		t.Errorf("expected custom error message, got: %s", rec.Body.String())
	}
}

func TestRedirectCustomRedirectHandler(t *testing.T) {
	mockDexServer := httptest.NewServer(mockSuccessfulDexAuthRedirect())
	defer mockDexServer.Close()

	issuerURL := mockDexServer.URL + "/login"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	customRedirectHandlerCalled := false
	customRedirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		customRedirectHandlerCalled = true
		cookie := frontdex.StateToken(r)
		authURL := frontdex.AuthorizationURL(r)

		// Custom logic: set cookie with custom attributes
		http.SetCookie(w, cookie)
		// Custom redirect with 307 instead of 302
		http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
	})

	fdx := frontdex.New(
		issuerURL,
		"test-client-id",
		"test-client-secret",
		frontdex.WithEndpointURL(mockDexServer.URL),
		frontdex.WithConnectors([]string{"github"}),
		frontdex.WithRedirectHandler(customRedirectHandler),
		frontdex.WithCookieSecure(false),
	)(handler)

	form := url.Values{}
	form.Set("via", "github")
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	fdx.ServeHTTP(rec, req)

	if !customRedirectHandlerCalled {
		t.Error("expected custom redirect handler to be called")
	}

	if rec.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected status %d, got %d", http.StatusTemporaryRedirect, rec.Code)
	}
}

func TestRedirectStateTokenGeneration(t *testing.T) {
	mockDexServer := httptest.NewServer(mockSuccessfulDexAuthRedirect())
	defer mockDexServer.Close()

	issuerURL := mockDexServer.URL + "/login"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	fdx := frontdex.New(
		issuerURL,
		"test-client-id",
		"test-client-secret",
		frontdex.WithEndpointURL(mockDexServer.URL),
		frontdex.WithConnectors([]string{"github"}),
		frontdex.WithCookieSecure(false),
	)(handler)

	form := url.Values{}
	form.Set("via", "github")

	// Make multiple requests and verify each gets unique state tokens
	states := make(map[string]bool)
	cookies := make(map[string]bool)

	for i := range 5 {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rec := httptest.NewRecorder()
		fdx.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Fatalf("iteration %d: expected status %d, got %d", i, http.StatusFound, rec.Code)
		}

		location := rec.Header().Get("Location")
		redirectURL, err := url.Parse(location)
		if err != nil {
			t.Fatalf("iteration %d: failed to parse redirect URL: %v", i, err)
		}

		state := redirectURL.Query().Get("state")
		if state == "" {
			t.Fatalf("iteration %d: expected state in redirect URL", i)
		}

		if states[state] {
			t.Errorf("iteration %d: duplicate state value: %s", i, state)
		}
		states[state] = true

		cookieList := rec.Result().Cookies()
		if len(cookieList) == 0 {
			t.Fatalf("iteration %d: expected cookie to be set", i)
		}

		cookieValue := cookieList[0].Value
		if cookies[cookieValue] {
			t.Errorf("iteration %d: duplicate cookie value", i)
		}
		cookies[cookieValue] = true
	}

	// Verify we got 5 unique states and 5 unique cookies
	if len(states) != 5 {
		t.Errorf("expected 5 unique states, got %d", len(states))
	}
	if len(cookies) != 5 {
		t.Errorf("expected 5 unique cookies, got %d", len(cookies))
	}
}

func TestRedirectPKCEParametersAndValidation(t *testing.T) {
	mockDexServer := httptest.NewServer(mockSuccessfulDexAuthRedirect())
	defer mockDexServer.Close()

	issuerURL := mockDexServer.URL + "/login"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	fdx := frontdex.New(
		issuerURL,
		"test-client-id",
		"test-client-secret",
		frontdex.WithEndpointURL(mockDexServer.URL),
		frontdex.WithConnectors([]string{"github"}),
		frontdex.WithCookieSecure(false),
	)(handler)

	form := url.Values{}
	form.Set("via", "github")
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	fdx.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, rec.Code)
	}

	location := rec.Header().Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse redirect URL: %v", err)
	}

	query := redirectURL.Query()

	// Verify PKCE parameters are present
	codeChallenge := query.Get("code_challenge")
	codeChallengeMethod := query.Get("code_challenge_method")

	if codeChallenge == "" {
		t.Error("expected code_challenge parameter")
	}

	if codeChallengeMethod != "S256" {
		t.Errorf("expected code_challenge_method 'S256', got %q", codeChallengeMethod)
	}

	// Verify code_challenge is valid base64url and has correct length
	decoded, err := base64.RawURLEncoding.DecodeString(codeChallenge)
	if err != nil {
		t.Errorf("code_challenge is not valid base64url: %v", err)
	} else if len(decoded) != 32 {
		t.Errorf("expected code_challenge to decode to 32 bytes, got %d", len(decoded))
	}
}
