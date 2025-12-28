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
	"github.com/tetsuo/frontdex/internal/crypto"
)

// Test helper functions for callback

// mockDexCallbackHandler creates a handler that properly responds to Dex callback requests
func mockDexCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the actual server URL from the request
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		baseURL := scheme + "://" + r.Host

		query := r.URL.Query()
		state := query.Get("state")
		code := query.Get("code")

		// Construct the callback URL using the actual server's URL
		callbackURL := baseURL + "/login/callback"
		u, _ := url.Parse(callbackURL)
		q := u.Query()
		q.Set("state", state)
		q.Set("code", code)
		u.RawQuery = q.Encode()

		w.Header().Set("Location", u.String())
		w.WriteHeader(http.StatusSeeOther)
	}
}

// Tests for callback flow

func TestCallbackMissingState(t *testing.T) {
	mockDexServer := httptest.NewServer(mockDexCallbackHandler())
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

	// Create a callback request without state parameter
	req := httptest.NewRequest(http.MethodGet, "/callback", nil)

	rec := httptest.NewRecorder()
	fdx.ServeHTTP(rec, req)

	// Should get a bad request error
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "state missing") {
		t.Errorf("expected error message to contain 'state missing', got: %s", body)
	}
}

func TestCallbackErrorParam(t *testing.T) {
	mockDexServer := httptest.NewServer(mockDexCallbackHandler())
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

	tests := []struct {
		name         string
		errorCode    string
		expectedCode int
	}{
		{
			name:         "access_denied",
			errorCode:    "access_denied",
			expectedCode: http.StatusForbidden,
		},
		{
			name:         "unverified_user_email",
			errorCode:    "unverified_user_email",
			expectedCode: http.StatusForbidden,
		},
		{
			name:         "invalid_request",
			errorCode:    "invalid_request",
			expectedCode: http.StatusInternalServerError,
		},
		{
			name:         "server_error",
			errorCode:    "server_error",
			expectedCode: http.StatusInternalServerError,
		},
		{
			name:         "unrecognized_error",
			errorCode:    "unrecognized_error",
			expectedCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/callback?state=test-state&error="+tt.errorCode, nil)

			rec := httptest.NewRecorder()
			fdx.ServeHTTP(rec, req)

			if rec.Code != tt.expectedCode {
				t.Errorf("expected status %d, got %d", tt.expectedCode, rec.Code)
			}
		})
	}
}

func TestCallbackMissingStateToken(t *testing.T) {
	mockDexServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This should handle the callback request and return to the configured redirect URL
		query := r.URL.Query()
		state := query.Get("state")
		code := query.Get("code")

		redirectURL := r.Header.Get("Referer")
		if redirectURL == "" {
			// Build from the request
			scheme := "http"
			host := r.Host
			redirectURL = scheme + "://" + host + "/login/callback"
		}

		u, _ := url.Parse(redirectURL)
		q := u.Query()
		q.Set("state", state)
		q.Set("code", code)
		u.RawQuery = q.Encode()

		w.Header().Set("Location", u.String())
		w.WriteHeader(http.StatusSeeOther)
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
		frontdex.WithCookieSecure(false),
	)(handler)

	req := httptest.NewRequest(http.MethodGet, "/callback?state=test-state&code=test-code", nil)

	rec := httptest.NewRecorder()
	fdx.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d (body: %s)", http.StatusBadRequest, rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	if !strings.Contains(body, "state token missing") {
		t.Errorf("expected error message to contain 'state token missing', got: %s", body)
	}
}

func TestCallbackInvalidBase64StateToken(t *testing.T) {
	mockDexServer := httptest.NewServer(mockDexCallbackHandler())
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

	// Create a callback request with invalid base64 cookie
	req := httptest.NewRequest(http.MethodGet, "/callback?state=test-state&code=test-code", nil)
	req.AddCookie(&http.Cookie{
		Name:    "_fdx.state",
		Value:   "not-valid-base64!!!",
		Expires: time.Now().Add(time.Minute * 1),
	})

	rec := httptest.NewRecorder()
	fdx.ServeHTTP(rec, req)

	//Should get a bad request error
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d (body: %s)", http.StatusBadRequest, rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	if !strings.Contains(body, "bad state token: illegal base64 data") {
		t.Errorf("expected error message to contain 'bad state token: illegal base64 data', got: %s", body)
	}
}

func TestCallbackCustomErrorHandler(t *testing.T) {
	mockDexServer := httptest.NewServer(mockDexCallbackHandler())
	defer mockDexServer.Close()

	issuerURL := mockDexServer.URL + "/login"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	customErrorCalled := false
	customErrorHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		customErrorCalled = true
		err := frontdex.FailureReason(r)
		statusCode := frontdex.StatusCodeFromError(err)
		w.WriteHeader(statusCode)
		w.Write([]byte("Custom callback error: " + err.Error()))
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

	// Trigger an error by missing state
	req := httptest.NewRequest(http.MethodGet, "/callback", nil)

	rec := httptest.NewRecorder()
	fdx.ServeHTTP(rec, req)

	if !customErrorCalled {
		t.Error("expected custom error handler to be called")
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Custom callback error") {
		t.Errorf("expected custom error message, got: %s", body)
	}
}

func TestCallbackDecryptStateToken(t *testing.T) {
	mockDexServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("should reach here. Path: %s", r.URL.Path)
	}))
	defer mockDexServer.Close()

	issuerURL := mockDexServer.URL + "/login"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	// wrong secret should fail to decrypt
	t.Run("wrong_secret", func(t *testing.T) {
		// Create a valid 172-byte token
		validToken := make([]byte, 172)
		for i := range validToken {
			validToken[i] = byte('A' + (i % 26))
		}

		// Encrypt with the correct secret
		cyp, err := crypto.NewAESCipher(secret)
		if err != nil {
			t.Fatalf("failed to create cipher: %v", err)
		}
		ciphertext, err := cyp.Encrypt(validToken)
		if err != nil {
			t.Fatalf("failed to encrypt: %v", err)
		}
		cookieValue := base64.RawURLEncoding.EncodeToString(ciphertext)
		stateCookie := &http.Cookie{
			Name:    "_fdx.state",
			Value:   cookieValue,
			Expires: time.Now().Add(time.Minute),
		}

		// Now create frontdex with a DIFFERENT secret
		wrongSecret := make([]byte, 32)
		for i := range wrongSecret {
			wrongSecret[i] = byte(255 - i)
		}

		fdxWrong := frontdex.New(
			issuerURL,
			"test-client-id",
			"test-client-secret",
			frontdex.WithEndpointURL(mockDexServer.URL),
			frontdex.WithConnectors([]string{"github"}),
			frontdex.WithStateSecret(wrongSecret),
			frontdex.WithCookieSecure(false),
		)(handler)

		req := httptest.NewRequest(http.MethodGet, "/callback?state=test-state&code=test-code", nil)
		req.AddCookie(stateCookie)

		rec := httptest.NewRecorder()
		fdxWrong.ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("expected status %d, got %d", http.StatusInternalServerError, rec.Code)
		}

		body := rec.Body.String()
		if !strings.Contains(body, "decrypt state") {
			t.Errorf("expected 'decrypt state' error, got: %s", body)
		}
	})

	// truncated encrypted token
	t.Run("truncated_ciphertext", func(t *testing.T) {
		truncatedCookie := &http.Cookie{
			Name:    "_fdx.state",
			Value:   "aGVsbG8", // Short base64 string - too small to be valid ciphertext
			Expires: time.Now().Add(time.Minute),
		}

		fdx := frontdex.New(
			issuerURL,
			"test-client-id",
			"test-client-secret",
			frontdex.WithEndpointURL(mockDexServer.URL),
			frontdex.WithConnectors([]string{"github"}),
			frontdex.WithStateSecret(secret),
			frontdex.WithCookieSecure(false),
		)(handler)

		req := httptest.NewRequest(http.MethodGet, "/callback?state=test-state&code=test-code", nil)
		req.AddCookie(truncatedCookie)

		rec := httptest.NewRecorder()
		fdx.ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("expected status %d, got %d", http.StatusInternalServerError, rec.Code)
		}

		body := rec.Body.String()
		if !strings.Contains(body, "decrypt state") {
			t.Errorf("expected 'decrypt state' error, got: %s", body)
		}
	})

	// valid decrypt but token too short (< 172 bytes)
	t.Run("token_too_short", func(t *testing.T) {
		// Create a short token (< 172 chars)
		shortToken := make([]byte, 50)
		for i := range shortToken {
			shortToken[i] = 'A'
		}

		// Encrypt with correct secret
		cyp, err := crypto.NewAESCipher(secret)
		if err != nil {
			t.Fatalf("failed to create cipher: %v", err)
		}
		ciphertext, err := cyp.Encrypt(shortToken)
		if err != nil {
			t.Fatalf("failed to encrypt: %v", err)
		}

		cookieValue := base64.RawURLEncoding.EncodeToString(ciphertext)
		stateCookie := &http.Cookie{
			Name:    "_fdx.state",
			Value:   cookieValue,
			Expires: time.Now().Add(time.Minute),
		}

		fdx := frontdex.New(
			issuerURL,
			"test-client-id",
			"test-client-secret",
			frontdex.WithEndpointURL(mockDexServer.URL),
			frontdex.WithConnectors([]string{"github"}),
			frontdex.WithStateSecret(secret),
			frontdex.WithCookieSecure(false),
		)(handler)

		req := httptest.NewRequest(http.MethodGet, "/callback?state=test-state&code=test-code", nil)
		req.AddCookie(stateCookie)

		rec := httptest.NewRecorder()
		fdx.ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("expected status %d, got %d", http.StatusInternalServerError, rec.Code)
		}

		body := rec.Body.String()
		if !strings.Contains(body, "invalid state token length") {
			t.Errorf("expected 'invalid state token length' error, got: %s", body)
		}
	})
}

func TestCallbackDexErrors(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Use a known secret for testing
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	tests := []struct {
		name               string
		mockHandler        http.HandlerFunc
		expectedStatusCode int
		expectedError      string
	}{
		{
			name: "dex_resource_unavailable",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				htmlResponse := `<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
<div class="theme-panel">
<h2>Bad Request</h2>
<p>Requested resource does not exist.</p>
</div>
</body>
</html>`
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(htmlResponse))
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedError:      "requested resource does not exist",
		},
		{
			name: "dex_user_session_error",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				htmlResponse := `<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
<div class="theme-panel">
<h2>Bad Request</h2>
<p>User session error.</p>
</div>
</body>
</html>`
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(htmlResponse))
			},
			expectedStatusCode: http.StatusInternalServerError,
			expectedError:      "user session error",
		},
		{
			name: "dex_invalid_connector",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				htmlResponse := `<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
<div class="theme-panel">
<h2>Bad Request</h2>
<p>Connector ID does not match a valid Connector</p>
</div>
</body>
</html>`
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(htmlResponse))
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedError:      "connector invalid",
		},
		{
			name: "dex_auth_failure_google_invalid_request",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				htmlResponse := `<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
<div class="theme-panel">
<h2>Internal Server Error</h2>
<p>Failed to authenticate: google: failed to get token: oauth2: "invalid_request" </p>
</div>
</body>
</html>`
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(htmlResponse))
			},
			expectedStatusCode: http.StatusForbidden,
			expectedError:      "failed to authenticate: google: invalid request",
		},
		{
			name: "dex_auth_failure_google_invalid_grant",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				htmlResponse := `<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
<div class="theme-panel">
<h2>Internal Server Error</h2>
<p>Failed to authenticate: google: failed to get token: oauth2: "invalid_grant" </p>
</div>
</body>
</html>`
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(htmlResponse))
			},
			expectedStatusCode: http.StatusForbidden,
			expectedError:      "failed to authenticate: google: invalid grant",
		},
		{
			name: "dex_auth_failure_github_bad_verification",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				htmlResponse := `<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
<div class="theme-panel">
<h2>Internal Server Error</h2>
<p>Failed to authenticate: github: failed to get token: oauth2: "bad_verification_code"</p>
</div>
</body>
</html>`
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(htmlResponse))
			},
			expectedStatusCode: http.StatusForbidden,
			expectedError:      "failed to authenticate: github: bad verification code",
		},
		{
			name: "dex_auth_failure_github_unverified_email",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				htmlResponse := `<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
<div class="theme-panel">
<h2>Internal Server Error</h2>
<p>Failed to authenticate: github: failed to get token: oauth2: "unverified_user_email"</p>
</div>
</body>
</html>`
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(htmlResponse))
			},
			expectedStatusCode: http.StatusForbidden,
			expectedError:      "failed to authenticate: github: unverified user email",
		},
		{
			name: "dex_unexpected_status",
			mockHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			expectedStatusCode: http.StatusInternalServerError,
			expectedError:      "dex returned unexpected status code: 404",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock Dex server that handles both auth and callback
			mockDexServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/auth" {
					// Handle auth redirect request
					query := r.URL.Query()
					externalAuthURL := url.URL{
						Scheme: "https",
						Host:   "example-provider.com",
						Path:   "/oauth/authorize",
					}
					q := externalAuthURL.Query()
					q.Set("client_id", "test-client-id")
					q.Set("redirect_uri", query.Get("redirect_uri"))
					q.Set("response_type", "code")
					q.Set("state", query.Get("state"))
					q.Set("nonce", query.Get("nonce"))
					if codeChallenge := query.Get("code_challenge"); codeChallenge != "" {
						q.Set("code_challenge", codeChallenge)
					}
					if codeChallengeMethod := query.Get("code_challenge_method"); codeChallengeMethod != "" {
						q.Set("code_challenge_method", codeChallengeMethod)
					}
					externalAuthURL.RawQuery = q.Encode()
					w.Header().Set("Location", externalAuthURL.String())
					w.WriteHeader(http.StatusFound)
				} else {
					// Handle callback request with the specific error from this test case
					tt.mockHandler(w, r)
				}
			}))
			defer mockDexServer.Close()

			fdx := frontdex.New(
				mockDexServer.URL+"/login",
				"test-client-id",
				"test-client-secret",
				frontdex.WithEndpointURL(mockDexServer.URL),
				frontdex.WithConnectors([]string{"github"}),
				frontdex.WithStateSecret(secret),
				frontdex.WithCookieSecure(false),
			)(handler)

			// First create a valid redirect to get a state cookie
			form := url.Values{}
			form.Set("via", "github")
			redirectReq := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
			redirectReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			redirectRec := httptest.NewRecorder()
			fdx.ServeHTTP(redirectRec, redirectReq)

			if redirectRec.Code != http.StatusFound {
				t.Fatalf("redirect failed with status %d", redirectRec.Code)
			}

			cookies := redirectRec.Result().Cookies()
			var stateCookie *http.Cookie
			for _, cookie := range cookies {
				if cookie.Name == "_fdx.state" {
					stateCookie = cookie
					break
				}
			}

			location := redirectRec.Header().Get("Location")
			redirectURL, err := url.Parse(location)
			if err != nil {
				t.Fatalf("failed to parse redirect URL: %v", err)
			}
			stateParam := redirectURL.Query().Get("state")

			// Now test the callback with the mock Dex error
			req := httptest.NewRequest(http.MethodGet, "/callback?state="+stateParam+"&code=test-code", nil)
			req.AddCookie(stateCookie)

			rec := httptest.NewRecorder()
			fdx.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatusCode {
				t.Errorf("expected status %d, got %d (body: %s)", tt.expectedStatusCode, rec.Code, rec.Body.String())
			}

			body := rec.Body.String()
			if !strings.Contains(body, tt.expectedError) {
				t.Errorf("expected error %q, got: %s", tt.expectedError, body)
			}
		})
	}
}

func TestCallbackStateMismatch(t *testing.T) {
	// Create a mock Dex server that handles both auth and callback
	mockDexServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth" {
			// Handle auth redirect request
			query := r.URL.Query()
			externalAuthURL := url.URL{
				Scheme: "https",
				Host:   "example-provider.com",
				Path:   "/oauth/authorize",
			}
			q := externalAuthURL.Query()
			q.Set("client_id", "test-client-id")
			q.Set("redirect_uri", query.Get("redirect_uri"))
			q.Set("response_type", "code")
			q.Set("state", query.Get("state"))
			q.Set("nonce", query.Get("nonce"))
			if codeChallenge := query.Get("code_challenge"); codeChallenge != "" {
				q.Set("code_challenge", codeChallenge)
			}
			if codeChallengeMethod := query.Get("code_challenge_method"); codeChallengeMethod != "" {
				q.Set("code_challenge_method", codeChallengeMethod)
			}
			externalAuthURL.RawQuery = q.Encode()
			w.Header().Set("Location", externalAuthURL.String())
			w.WriteHeader(http.StatusFound)
		} else {
			// Return a different state than what was sent
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			baseURL := scheme + "://" + r.Host

			callbackURL := baseURL + "/login/callback"
			u, _ := url.Parse(callbackURL)
			q := u.Query()
			// Return wrong state
			q.Set("state", "wrong-state-value-0123456789012345678901")
			q.Set("code", "test-code")
			u.RawQuery = q.Encode()

			w.Header().Set("Location", u.String())
			w.WriteHeader(http.StatusSeeOther)
		}
	}))
	defer mockDexServer.Close()

	issuerURL := mockDexServer.URL + "/login"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	fdx := frontdex.New(
		issuerURL,
		"test-client-id",
		"test-client-secret",
		frontdex.WithEndpointURL(mockDexServer.URL),
		frontdex.WithConnectors([]string{"github"}),
		frontdex.WithStateSecret(secret),
		frontdex.WithCookieSecure(false),
	)(handler)

	// Create a valid redirect first
	form := url.Values{}
	form.Set("via", "github")
	redirectReq := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	redirectReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	redirectRec := httptest.NewRecorder()
	fdx.ServeHTTP(redirectRec, redirectReq)

	if redirectRec.Code != http.StatusFound {
		t.Fatalf("redirect failed with status %d", redirectRec.Code)
	}

	cookies := redirectRec.Result().Cookies()
	var stateCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "_fdx.state" {
			stateCookie = cookie
			break
		}
	}

	location := redirectRec.Header().Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse redirect URL: %v", err)
	}
	stateParam := redirectURL.Query().Get("state")

	// Test callback with mismatched state
	req := httptest.NewRequest(http.MethodGet, "/callback?state="+stateParam+"&code=test-code", nil)
	req.AddCookie(stateCookie)

	rec := httptest.NewRecorder()
	fdx.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "state mismatch") {
		t.Errorf("expected 'state mismatch' error, got: %s", body)
	}
}

func TestCallbackExchangeErrors(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	tests := []struct {
		name               string
		mockTokenHandler   func(w http.ResponseWriter, r *http.Request)
		expectedStatusCode int
		expectedError      string
	}{
		{
			name: "exchange_invalid_code",
			mockTokenHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"invalid_grant","error_description":"Invalid authorization code"}`))
			},
			expectedStatusCode: http.StatusInternalServerError,
			expectedError:      "exchange code",
		},
		{
			name: "exchange_timeout",
			mockTokenHandler: func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(2 * time.Second)
				w.WriteHeader(http.StatusOK)
			},
			expectedStatusCode: http.StatusInternalServerError,
			expectedError:      "exchange code",
		},
		{
			name: "exchange_server_error",
			mockTokenHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectedStatusCode: http.StatusInternalServerError,
			expectedError:      "exchange code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock Dex server that handles auth, callback, and token endpoints
			mockDexServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/auth":
					// Handle auth redirect request
					query := r.URL.Query()
					externalAuthURL := url.URL{
						Scheme: "https",
						Host:   "example-provider.com",
						Path:   "/oauth/authorize",
					}
					q := externalAuthURL.Query()
					q.Set("client_id", "test-client-id")
					q.Set("redirect_uri", query.Get("redirect_uri"))
					q.Set("response_type", "code")
					q.Set("state", query.Get("state"))
					q.Set("nonce", query.Get("nonce"))
					if codeChallenge := query.Get("code_challenge"); codeChallenge != "" {
						q.Set("code_challenge", codeChallenge)
					}
					if codeChallengeMethod := query.Get("code_challenge_method"); codeChallengeMethod != "" {
						q.Set("code_challenge_method", codeChallengeMethod)
					}
					externalAuthURL.RawQuery = q.Encode()
					w.Header().Set("Location", externalAuthURL.String())
					w.WriteHeader(http.StatusFound)
				case "/token":
					tt.mockTokenHandler(w, r)
				case "/keys":
					// Return empty JWKS for now
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(`{"keys":[]}`))
				default:
					// Handle callback request - return matching state and code
					scheme := "http"
					if r.TLS != nil {
						scheme = "https"
					}
					baseURL := scheme + "://" + r.Host
					callbackURL := baseURL + "/login/callback"
					u, _ := url.Parse(callbackURL)
					q := u.Query()
					q.Set("state", r.URL.Query().Get("state"))
					q.Set("code", "test-auth-code")
					u.RawQuery = q.Encode()
					w.Header().Set("Location", u.String())
					w.WriteHeader(http.StatusSeeOther)
				}
			}))
			defer mockDexServer.Close()

			opts := []frontdex.Option{
				frontdex.WithEndpointURL(mockDexServer.URL),
				frontdex.WithConnectors([]string{"github"}),
				frontdex.WithStateSecret(secret),
				frontdex.WithCookieSecure(false),
			}

			if tt.name == "exchange_timeout" {
				opts = append(opts, frontdex.WithHTTPClientTimeout(100*time.Millisecond))
			}

			fdx := frontdex.New(
				mockDexServer.URL+"/login",
				"test-client-id",
				"test-client-secret",
				opts...,
			)(handler)

			// First create a valid redirect to get a state cookie
			form := url.Values{}
			form.Set("via", "github")
			redirectReq := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
			redirectReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			redirectRec := httptest.NewRecorder()
			fdx.ServeHTTP(redirectRec, redirectReq)

			if redirectRec.Code != http.StatusFound {
				t.Fatalf("redirect failed with status %d", redirectRec.Code)
			}

			cookies := redirectRec.Result().Cookies()
			var stateCookie *http.Cookie
			for _, cookie := range cookies {
				if cookie.Name == "_fdx.state" {
					stateCookie = cookie
					break
				}
			}

			location := redirectRec.Header().Get("Location")
			redirectURL, err := url.Parse(location)
			if err != nil {
				t.Fatalf("failed to parse redirect URL: %v", err)
			}
			stateParam := redirectURL.Query().Get("state")

			// Now test the callback with the exchange error
			req := httptest.NewRequest(http.MethodGet, "/callback?state="+stateParam+"&code=test-code", nil)
			req.AddCookie(stateCookie)

			rec := httptest.NewRecorder()
			fdx.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatusCode {
				t.Errorf("expected status %d, got %d (body: %s)", tt.expectedStatusCode, rec.Code, rec.Body.String())
			}

			body := rec.Body.String()
			if !strings.Contains(body, tt.expectedError) {
				t.Errorf("expected error %q, got: %s", tt.expectedError, body)
			}
		})
	}
}
