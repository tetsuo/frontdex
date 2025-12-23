package api_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/tetsuo/frontdex/api"
)

// Test that ExchangeCodeForToken validates parameters
func TestExchangeErrorInvalidCode(t *testing.T) {
	mockDexServer := createMockDexServer(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/keys":
			// Return empty JWKS
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"keys":[]}`))
		case "/token":
			// Return error for invalid code
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"invalid_grant","error_description":"Invalid authorization code"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer mockDexServer.Close()

	dex := setupTestDex(t, mockDexServer.URL)
	ctx := context.Background()

	exchangeReq := &api.ExchangeRequest{
		Verifier: []byte("test-verifier"),
		Code:     "invalid-code",
	}

	_, err := dex.ExchangeCodeForToken(ctx, exchangeReq)
	if err == nil {
		t.Fatal("expected error but got none")
	}

	// oauth2 library wraps the error, just verify we got an error
	if err.Error() == "" {
		t.Error("expected non-empty error message")
	}
}
