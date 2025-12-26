package frontdex

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/tetsuo/frontdex/dex"
)

// handleCallback completes the login process after the user returns from the identity provider.
// It checks for errors, validates the state, decrypts the login info from the cookie,
// and exchanges the code for a user token.
func (fdx *frontdex) handleCallback(r *http.Request) (*dex.Payload, error) {
	query := r.URL.Query()

	// All flows require a 'state' param
	if query.Get("state") == "" {
		return nil, ErrNoState
	}

	// If the error param exists, Dex will refuse to execute the callback even when state and
	// code params are present (except for the mock connector).
	if errorCode := query.Get("error"); errorCode != "" {
		// Handle recognized errors.
		if knownError, isKnownError := oauthErrors[errorCode]; isKnownError {
			return nil, knownError
		}
		return nil, ErrBadError
	}

	// Exchange callback params.
	callbackReq := &dex.CallbackRequest{
		RawQuery: r.URL.RawQuery,
		ClientIP: fdx.opts.RealIP.FromRequest(r),
	}

	state, code, err := fdx.dex.Callback(r.Context(), callbackReq)
	if err != nil {
		// State missing: ErrUserSession
		// Provided state does not resolve to a resource: ErrResourceUnavailable
		// Bad verification code: ErrAuthFailure
		return nil, err
	}

	// Validate and decrypt the token from the cookie.
	cookie, err := r.Cookie(fdx.opts.CookieFactory.CookieName)
	if err != nil {
		return nil, ErrMissingStateToken
	}

	if err := cookie.Valid(); err != nil {
		return nil, fmt.Errorf("%w: cookie: %v", ErrBadStateToken, err)
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadStateToken, err)
	}

	secret, err := fdx.cyp.Decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt state: %v", err)
	}

	if len(secret) < verifierEnd {
		return nil, fmt.Errorf("invalid state token length: want %d, got %d", verifierEnd, len(secret))
	}

	// Ensure state values match.
	if !equalStringBytes(state, secret[0:stateEnd]) {
		return nil, ErrStateMismatch
	}

	// Exchange code with oauth2 token and claims.
	exchangeReq := &dex.ExchangeRequest{
		Code:     code,
		Verifier: secret[nonceEnd:verifierEnd],
	}

	payload, err := fdx.dex.ExchangeCodeForToken(r.Context(), exchangeReq)
	if err != nil {
		return nil, fmt.Errorf("exchange code: %v", err)
	}

	// Ensure nonce values match.
	if !equalStringBytes(payload.IDToken.Nonce, secret[stateEnd:nonceEnd]) {
		return nil, fmt.Errorf("nonce mismatch: want %s, got %s", string(secret[stateEnd:nonceEnd]), payload.IDToken.Nonce)
	}

	// Check token lifetime.
	expectedTTL := fdx.opts.TokenTTL

	expiresIn, ok := payload.Token.Extra("expires_in").(float64)
	if !ok || expiresIn < 1 || expiresIn > expectedTTL.Seconds()+1 {
		return nil, fmt.Errorf("'expires_in' out of range: want shorter duration than %.1fs, got %.1fs", expectedTTL.Seconds()+1, expiresIn)
	}

	lifetime := payload.IDToken.Expiry.Sub(payload.IDToken.IssuedAt)
	if lifetime > expectedTTL+time.Second || lifetime < time.Second {
		return nil, fmt.Errorf("'invalid ID token lifetime: want shorter duration than %.1fs, got %.1fs", expectedTTL.Seconds(), lifetime.Seconds())
	}

	return payload, nil
}

var oauthErrors = map[string]error{
	// https://docs.github.com/en/apps/oauth-apps/maintaining-oauth-apps/troubleshooting-authorization-request-errors
	"application_suspended": errors.New("application suspended"),
	"redirect_uri_mismatch": errors.New("redirect uri mismatch"),
	"access_denied":         ErrAccessDenied,
	"unverified_user_email": ErrAccessDenied,
	"invalid_request":       errors.New("invalid request"),
	"request_not_supported": errors.New("request not supported"),
	// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
	"unauthorized_client":       errors.New("unauthorized client"),
	"unsupported_response_type": errors.New("unsupported response type"),
	"invalid_scope":             errors.New("invalid scope"),
	"server_error":              errors.New("server error"),
	"temporarily_unavailable":   errors.New("temporarily unavailable"),
	// https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#error-codes-for-the-device-flow
	"authorization_pending":        errors.New("authorization pending"),
	"slow_down":                    errors.New("slow down"),
	"expired_token":                errors.New("expired token"),
	"unsupported_grant_type":       errors.New("unsupported grant type"),
	"incorrect_client_credentials": errors.New("incorrect client credentials"),
	"incorrect_device_code":        errors.New("incorrect device code"),
	"device_flow_disabled":         errors.New("device flow disabled"),
	// https://developers.google.com/identity/protocols/oauth2/service-account#error-codes
	"admin_policy_enforced": errors.New("admin policy enforced"),
	"invalid_client":        errors.New("invalid client"),
	"deleted_client":        errors.New("deleted client"),
	"invalid_grant":         errors.New("invalid grant"),
	"disabled_client":       errors.New("disabled client"),
	"org_internal":          errors.New("org internal"),
}

func equalStringBytes(x string, y []byte) bool {
	if len(x) != len(y) {
		return false
	}
	for i := 0; i < len(x); i++ {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
