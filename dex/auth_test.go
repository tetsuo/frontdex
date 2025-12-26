package dex_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/tetsuo/frontdex/dex"
	"golang.org/x/oauth2"
)

// Test helper functions

func setupTestDex(t *testing.T, serverURL string) *dex.Dex {
	t.Helper()
	ctx := context.Background()

	providerCfg := oidc.ProviderConfig{
		IssuerURL:   serverURL,
		AuthURL:     serverURL + "/auth",
		JWKSURL:     serverURL + "/keys",
		UserInfoURL: serverURL + "/userinfo",
	}
	provider := providerCfg.NewProvider(ctx)

	oauth2cfg := &oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://example.com/callback",
		Scopes:       []string{"openid", "profile", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  serverURL + "/auth",
			TokenURL: serverURL + "/token",
		},
	}

	dex, err := dex.NewDex(http.DefaultTransport, oauth2cfg, provider, "", time.Second*10)
	if err != nil {
		t.Fatalf("NewDex failed: %v", err)
	}

	return dex
}

func createMockDexServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

func mockSuccessGoogle(w http.ResponseWriter, r *http.Request) {
	googleAuthURL := url.URL{
		Scheme: "https",
		Host:   "accounts.google.com",
		Path:   "/o/oauth2/v2/auth",
	}
	query := r.URL.Query()
	q := googleAuthURL.Query()
	q.Set("client_id", "test-client-id")
	q.Set("redirect_uri", "https://example.com/callback")
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email")
	q.Set("state", query.Get("state"))
	googleAuthURL.RawQuery = q.Encode()

	w.Header().Set("Location", googleAuthURL.String())
	w.WriteHeader(http.StatusFound)
}

func mockSuccessGitHub(w http.ResponseWriter, r *http.Request) {
	githubAuthURL := url.URL{
		Scheme: "https",
		Host:   "github.com",
		Path:   "/login/oauth/authorize",
	}
	query := r.URL.Query()
	q := githubAuthURL.Query()
	q.Set("client_id", "test-client-id")
	q.Set("redirect_uri", "https://example.com/callback")
	q.Set("response_type", "code")
	q.Set("scope", "user:email")
	q.Set("state", query.Get("state"))
	githubAuthURL.RawQuery = q.Encode()

	w.Header().Set("Location", githubAuthURL.String())
	w.WriteHeader(http.StatusFound)
}

func mockErrorResponse(w http.ResponseWriter, r *http.Request, errorCode, errorDescription string) {
	callbackURL := url.URL{
		Scheme: "https",
		Host:   "example.com",
		Path:   "/callback",
	}
	q := callbackURL.Query()
	q.Set("error", errorCode)
	q.Set("error_description", errorDescription)
	q.Set("state", r.URL.Query().Get("state"))
	callbackURL.RawQuery = q.Encode()

	w.Header().Set("Location", callbackURL.String())
	w.WriteHeader(http.StatusSeeOther)
}

// Tests

func TestPerformAuthRedirectGoogle(t *testing.T) {
	var requests []*http.Request

	mockDexServer := createMockDexServer(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r)
		mockSuccessGoogle(w, r)
	})
	defer mockDexServer.Close()

	client := setupTestDex(t, mockDexServer.URL)
	ctx := context.Background()

	authReq := &dex.AuthRequest{
		State:         "test-state-12345",
		Nonce:         "test-nonce-67890",
		CodeChallenge: "test-code-challenge",
		Via:           dex.ConnectorGoogle,
		ClientIP:      "192.168.1.1",
	}

	redirectURL, err := client.GetAuthorizationURL(ctx, authReq)
	if err != nil {
		t.Fatalf("PerformAuthRedirect failed: %v", err)
	}

	// Verify we got at least one request
	if len(requests) < 1 {
		t.Fatalf("expected at least 1 request to mock server, got %d", len(requests))
	}

	req := requests[0]

	// Verify query parameters on the initial request
	receivedQuery := req.URL.Query()
	if receivedQuery.Get("state") != "test-state-12345" {
		t.Errorf("expected state test-state-12345, got %s", receivedQuery.Get("state"))
	}
	if receivedQuery.Get("code_challenge") != "test-code-challenge" {
		t.Errorf("expected code_challenge test-code-challenge, got %s", receivedQuery.Get("code_challenge"))
	}
	if receivedQuery.Get("code_challenge_method") != "S256" {
		t.Errorf("expected code_challenge_method S256, got %s", receivedQuery.Get("code_challenge_method"))
	}
	if receivedQuery.Get("nonce") != "test-nonce-67890" {
		t.Errorf("expected nonce test-nonce-67890, got %s", receivedQuery.Get("nonce"))
	}
	if receivedQuery.Get("connector_id") != "google" {
		t.Errorf("expected connector_id google, got %s", receivedQuery.Get("connector_id"))
	}

	// Verify X-Forwarded-For header
	receivedXFF := req.Header.Get("X-Forwarded-For")
	if receivedXFF != "192.168.1.1" {
		t.Errorf("expected X-Forwarded-For 192.168.1.1, got %s", receivedXFF)
	}

	// Verify the returned URL is a valid Google OAuth URL
	u, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("failed to parse redirect URL: %v", err)
	}

	if u.Scheme != "https" {
		t.Errorf("expected scheme https, got %s", u.Scheme)
	}
	if u.Host != "accounts.google.com" {
		t.Errorf("expected host accounts.google.com, got %s", u.Host)
	}
	if u.Path != "/o/oauth2/v2/auth" {
		t.Errorf("expected path /o/oauth2/v2/auth, got %s", u.Path)
	}

	query := u.Query()
	if query.Get("client_id") != "test-client-id" {
		t.Errorf("expected client_id test-client-id, got %s", query.Get("client_id"))
	}
	if query.Get("redirect_uri") != "https://example.com/callback" {
		t.Errorf("expected redirect_uri https://example.com/callback, got %s", query.Get("redirect_uri"))
	}
	if query.Get("response_type") != "code" {
		t.Errorf("expected response_type code, got %s", query.Get("response_type"))
	}
	if query.Get("scope") != "openid profile email" {
		t.Errorf("expected scope 'openid profile email', got %s", query.Get("scope"))
	}
}

func TestPerformAuthRedirectGitHub(t *testing.T) {
	mockDexServer := createMockDexServer(mockSuccessGitHub)
	defer mockDexServer.Close()

	client := setupTestDex(t, mockDexServer.URL)
	ctx := context.Background()

	authReq := &dex.AuthRequest{
		State:         "test-state-12345",
		Nonce:         "test-nonce-67890",
		CodeChallenge: "test-code-challenge",
		Via:           dex.ConnectorGitHub,
	}

	redirectURL, err := client.GetAuthorizationURL(ctx, authReq)
	if err != nil {
		t.Fatalf("PerformAuthRedirect failed: %v", err)
	}

	// Verify the returned URL is a valid GitHub OAuth URL
	u, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("failed to parse redirect URL: %v", err)
	}

	if u.Host != "github.com" {
		t.Errorf("expected host github.com, got %s", u.Host)
	}
	if u.Path != "/login/oauth/authorize" {
		t.Errorf("expected path /login/oauth/authorize, got %s", u.Path)
	}
}

func TestPerformAuthRedirectErrorMissingResponseType(t *testing.T) {
	mockDexServer := createMockDexServer(func(w http.ResponseWriter, r *http.Request) {
		mockErrorResponse(w, r, "invalid_request", "No response_type provided")
	})
	defer mockDexServer.Close()

	client := setupTestDex(t, mockDexServer.URL)
	ctx := context.Background()

	authReq := &dex.AuthRequest{
		State:         "test-state",
		Nonce:         "test-nonce",
		CodeChallenge: "test-challenge",
		Via:           dex.ConnectorGoogle,
	}

	_, err := client.GetAuthorizationURL(ctx, authReq)
	if err == nil {
		t.Fatal("expected error but got none")
	}

	expectedError := "invalid_request: No response_type provided"
	if err.Error() != expectedError {
		t.Errorf("expected error %q, got %q", expectedError, err.Error())
	}
}

func TestPerformAuthRedirectErrorInvalidScope(t *testing.T) {
	mockDexServer := createMockDexServer(func(w http.ResponseWriter, r *http.Request) {
		mockErrorResponse(w, r, "invalid_scope", `Missing required scope(s) ["openid"].`)
	})
	defer mockDexServer.Close()

	client := setupTestDex(t, mockDexServer.URL)
	ctx := context.Background()

	authReq := &dex.AuthRequest{
		State:         "test-state",
		Nonce:         "test-nonce",
		CodeChallenge: "test-challenge",
		Via:           dex.ConnectorGoogle,
	}

	_, err := client.GetAuthorizationURL(ctx, authReq)
	if err == nil {
		t.Fatal("expected error but got none")
	}

	expectedError := `invalid_scope: Missing required scope(s) ["openid"].`
	if err.Error() != expectedError {
		t.Errorf("expected error %q, got %q", expectedError, err.Error())
	}
}

func TestPerformAuthRedirectErrorInvalidCodeChallengeMethod(t *testing.T) {
	mockDexServer := createMockDexServer(func(w http.ResponseWriter, r *http.Request) {
		mockErrorResponse(w, r, "invalid_request", `Unsupported PKCE challenge method ("INVALID").`)
	})
	defer mockDexServer.Close()

	client := setupTestDex(t, mockDexServer.URL)
	ctx := context.Background()

	authReq := &dex.AuthRequest{
		State:         "test-state",
		Nonce:         "test-nonce",
		CodeChallenge: "test-challenge",
		Via:           dex.ConnectorGoogle,
	}

	_, err := client.GetAuthorizationURL(ctx, authReq)
	if err == nil {
		t.Fatal("expected error but got none")
	}

	expectedError := `invalid_request: Unsupported PKCE challenge method ("INVALID").`
	if err.Error() != expectedError {
		t.Errorf("expected error %q, got %q", expectedError, err.Error())
	}
}

func TestPerformAuthRedirectErrorNotFound(t *testing.T) {
	mockDexServer := createMockDexServer(func(w http.ResponseWriter, r *http.Request) {
		// Simulate 404 for missing client_id or redirect_uri (no Location header)
		w.WriteHeader(http.StatusNotFound)
	})
	defer mockDexServer.Close()

	client := setupTestDex(t, mockDexServer.URL)
	ctx := context.Background()

	authReq := &dex.AuthRequest{
		State:         "test-state",
		Nonce:         "test-nonce",
		CodeChallenge: "test-challenge",
		Via:           dex.ConnectorGoogle,
	}

	_, err := client.GetAuthorizationURL(ctx, authReq)
	if err == nil {
		t.Fatal("expected error but got none")
	}

	// Now should correctly return 404 error, not "missing location header"
	expectedError := "dex returned 404, but no error information found in HTML"
	if err.Error() != expectedError {
		t.Errorf("expected error %q, got %q", expectedError, err.Error())
	}
}

func TestPerformAuthRedirectErrorMissingLocationHeader(t *testing.T) {
	mockDexServer := createMockDexServer(func(w http.ResponseWriter, r *http.Request) {
		// Return 302 but without Location header - unusual case
		w.WriteHeader(http.StatusFound)
	})
	defer mockDexServer.Close()

	client := setupTestDex(t, mockDexServer.URL)
	ctx := context.Background()

	authReq := &dex.AuthRequest{
		State:         "test-state",
		Nonce:         "test-nonce",
		CodeChallenge: "test-challenge",
		Via:           dex.ConnectorGoogle,
	}

	_, err := client.GetAuthorizationURL(ctx, authReq)
	if err == nil {
		t.Fatal("expected error but got none")
	}

	expectedError := "missing Location header in dex 302 response"
	if err.Error() != expectedError {
		t.Errorf("expected error %q, got %q", expectedError, err.Error())
	}
}

func TestPerformAuthRedirectErrorUnexpectedStatusCode(t *testing.T) {
	mockDexServer := createMockDexServer(func(w http.ResponseWriter, r *http.Request) {
		// Return an unexpected status code like 500
		w.Header().Set("Location", "https://example.com/error")
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer mockDexServer.Close()

	client := setupTestDex(t, mockDexServer.URL)
	ctx := context.Background()

	authReq := &dex.AuthRequest{
		State:         "test-state",
		Nonce:         "test-nonce",
		CodeChallenge: "test-challenge",
		Via:           dex.ConnectorGoogle,
	}

	_, err := client.GetAuthorizationURL(ctx, authReq)
	if err == nil {
		t.Fatal("expected error but got none")
	}

	expectedError := "dex returned 500, but no error information found in HTML"
	if err.Error() != expectedError {
		t.Errorf("expected error %q, got %q", expectedError, err.Error())
	}
}

func TestPerformAuthRedirectError303WithoutErrorParams(t *testing.T) {
	mockDexServer := createMockDexServer(func(w http.ResponseWriter, r *http.Request) {
		// Return 303 but without error parameters - unusual case
		callbackURL := url.URL{
			Scheme: "https",
			Host:   "example.com",
			Path:   "/callback",
		}
		w.Header().Set("Location", callbackURL.String())
		w.WriteHeader(http.StatusSeeOther)
	})
	defer mockDexServer.Close()

	client := setupTestDex(t, mockDexServer.URL)
	ctx := context.Background()

	authReq := &dex.AuthRequest{
		State:         "test-state",
		Nonce:         "test-nonce",
		CodeChallenge: "test-challenge",
		Via:           dex.ConnectorGoogle,
	}

	_, err := client.GetAuthorizationURL(ctx, authReq)
	if err == nil {
		t.Fatal("expected error but got none")
	}

	expectedError := "dex returned 303 but no error information found in Location"
	if err.Error() != expectedError {
		t.Errorf("expected error %q, got %q", expectedError, err.Error())
	}
}
