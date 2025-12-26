package dex_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/tetsuo/frontdex/dex"
)

// Test helper functions for callback

func mockSuccessCallback(w http.ResponseWriter, r *http.Request) {
	redirectURL := url.URL{
		Scheme: "https",
		Host:   "example.com",
		Path:   "/callback",
	}
	q := redirectURL.Query()
	// Generate valid dex state (43 chars, alphanumeric + - and _)
	q.Set("state", "abcdefghijklmnopqrstuvwxyz_ABCDEFGHIJKLMN01")
	// Generate valid dex code (25 chars, lowercase alphanumeric)
	q.Set("code", "abcdefghijklmnopqrstuvwxy")
	redirectURL.RawQuery = q.Encode()

	w.Header().Set("Location", redirectURL.String())
	w.WriteHeader(http.StatusSeeOther)
}

func mockCallbackErrorHTML(w http.ResponseWriter, r *http.Request) {
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
}

// Tests

func TestCallbackSuccess(t *testing.T) {
	mockDexServer := createMockDexServer(mockSuccessCallback)
	defer mockDexServer.Close()

	client := setupTestDex(t, mockDexServer.URL)
	ctx := context.Background()

	callbackReq := &dex.CallbackRequest{
		RawQuery: "?state=user-provided-state&code=auth-code",
		ClientIP: "192.168.1.1",
	}

	state, code, err := client.Callback(ctx, callbackReq)
	if err != nil {
		t.Fatalf("Callback failed: %v", err)
	}
	// Check values directly instead of lengths
	expectedState := "abcdefghijklmnopqrstuvwxyz_ABCDEFGHIJKLMN01"
	expectedCode := "abcdefghijklmnopqrstuvwxy"

	if state != expectedState {
		t.Errorf("expected state %q, got %q", expectedState, state)
	}

	if code != expectedCode {
		t.Errorf("expected code %q, got %q", expectedCode, code)
	}
}

func TestCallbackSuccessWithClientIP(t *testing.T) {
	var requests []*http.Request

	mockDexServer := createMockDexServer(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r)
		mockSuccessCallback(w, r)
	})
	defer mockDexServer.Close()

	client := setupTestDex(t, mockDexServer.URL)
	ctx := context.Background()

	callbackReq := &dex.CallbackRequest{
		RawQuery: "?state=user-provided-state&code=auth-code",
		ClientIP: "10.0.0.5",
	}

	_, _, err := client.Callback(ctx, callbackReq)
	if err != nil {
		t.Fatalf("Callback failed: %v", err)
	}

	// Verify X-Forwarded-For header was set
	if len(requests) < 1 {
		t.Fatalf("expected at least 1 request to mock server, got %d", len(requests))
	}

	req := requests[0]
	receivedXFF := req.Header.Get("X-Forwarded-For")
	if receivedXFF != "10.0.0.5" {
		t.Errorf("expected X-Forwarded-For 10.0.0.5, got %s", receivedXFF)
	}
}

func TestCallbackErrorWrongRedirectURL(t *testing.T) {
	mockDexServer := createMockDexServer(func(w http.ResponseWriter, r *http.Request) {
		redirectURL := url.URL{
			Scheme: "https",
			Host:   "wrong-domain.com", // Wrong host
			Path:   "/callback",
		}
		q := redirectURL.Query()
		q.Set("state", "abcdefghijklmnopqrstuvwxyz_ABCDEFGHIJKLMN01")
		q.Set("code", "abcdefghijklmnopqrstuvwxy")
		redirectURL.RawQuery = q.Encode()

		w.Header().Set("Location", redirectURL.String())
		w.WriteHeader(http.StatusSeeOther)
	})
	defer mockDexServer.Close()

	client := setupTestDex(t, mockDexServer.URL)
	ctx := context.Background()

	callbackReq := &dex.CallbackRequest{
		RawQuery: "?state=user-state&code=auth-code",
	}

	_, _, err := client.Callback(ctx, callbackReq)
	if err == nil {
		t.Fatal("expected error but got none")
	}

	// Should fail parsing the callback due to wrong redirect URL
	if err.Error() != "expected callback URL \"https://example.com/callback\", got \"https://wrong-domain.com/callback\"" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCallbackErrorMissingLocationHeader(t *testing.T) {
	mockDexServer := createMockDexServer(func(w http.ResponseWriter, r *http.Request) {
		// Return 303 but without Location header - unusual case
		w.WriteHeader(http.StatusSeeOther)
	})
	defer mockDexServer.Close()

	client := setupTestDex(t, mockDexServer.URL)
	ctx := context.Background()

	callbackReq := &dex.CallbackRequest{
		RawQuery: "?state=user-state&code=auth-code",
	}

	_, _, err := client.Callback(ctx, callbackReq)
	if err == nil {
		t.Fatal("expected error but got none")
	}

	expectedError := "missing Location header in dex 303 response"
	if err.Error() != expectedError {
		t.Errorf("expected error %q, got %q", expectedError, err.Error())
	}
}

func TestCallbackErrorBadRequestHTML(t *testing.T) {
	mockDexServer := createMockDexServer(mockCallbackErrorHTML)
	defer mockDexServer.Close()

	client := setupTestDex(t, mockDexServer.URL)
	ctx := context.Background()

	callbackReq := &dex.CallbackRequest{
		RawQuery: "?state=invalid-state",
	}

	_, _, err := client.Callback(ctx, callbackReq)
	if err == nil {
		t.Fatal("expected error but got none")
	}

	// Should parse the HTML error - uses sentinel error ErrResourceUnavailable
	expectedError := "requested resource does not exist"
	if err.Error() != expectedError {
		t.Errorf("expected error %q, got %q", expectedError, err.Error())
	}
}

func TestCallbackErrorInternalServerHTML(t *testing.T) {
	mockDexServer := createMockDexServer(func(w http.ResponseWriter, r *http.Request) {
		htmlResponse := `<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
<div class="theme-panel">
<h2>Internal Server Error</h2>
<p>Something went wrong.</p>
</div>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(htmlResponse))
	})
	defer mockDexServer.Close()

	client := setupTestDex(t, mockDexServer.URL)
	ctx := context.Background()

	callbackReq := &dex.CallbackRequest{
		RawQuery: "?state=user-state&code=auth-code",
	}

	_, _, err := client.Callback(ctx, callbackReq)
	if err == nil {
		t.Fatal("expected error but got none")
	}

	expectedError := "Internal Server Error: Something went wrong."
	if err.Error() != expectedError {
		t.Errorf("expected error %q, got %q", expectedError, err.Error())
	}
}

func TestCallbackErrorUnexpectedStatusCode(t *testing.T) {
	mockDexServer := createMockDexServer(func(w http.ResponseWriter, r *http.Request) {
		// Return unexpected status code like 404
		w.WriteHeader(http.StatusNotFound)
	})
	defer mockDexServer.Close()

	client := setupTestDex(t, mockDexServer.URL)
	ctx := context.Background()

	callbackReq := &dex.CallbackRequest{
		RawQuery: "?state=user-state&code=auth-code",
	}

	_, _, err := client.Callback(ctx, callbackReq)
	if err == nil {
		t.Fatal("expected error but got none")
	}

	expectedError := "dex returned unexpected status code: 404"
	if err.Error() != expectedError {
		t.Errorf("expected error %q, got %q", expectedError, err.Error())
	}
}

func TestCallbackErrorNoHTMLErrorInfo(t *testing.T) {
	mockDexServer := createMockDexServer(func(w http.ResponseWriter, r *http.Request) {
		// Return 400 but with HTML that doesn't contain error info
		htmlResponse := `<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
<p>Some error occurred but no theme-panel.</p>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(htmlResponse))
	})
	defer mockDexServer.Close()

	client := setupTestDex(t, mockDexServer.URL)
	ctx := context.Background()

	callbackReq := &dex.CallbackRequest{
		RawQuery: "?state=user-state&code=auth-code",
	}

	_, _, err := client.Callback(ctx, callbackReq)
	if err == nil {
		t.Fatal("expected error but got none")
	}

	expectedError := "dex returned 400, but no error information found in HTML"
	if err.Error() != expectedError {
		t.Errorf("expected error %q, got %q", expectedError, err.Error())
	}
}
