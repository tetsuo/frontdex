package dex

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// ExchangeRequest contains the code and verifier for exchanging with Dex for tokens.
type ExchangeRequest struct {
	Verifier []byte // PKCE verifier value
	Code     string // Authorization code from callback
}

// Claims contains the user's identity and profile information from Dex.
type Claims struct {
	Subject           string          `json:"sub"`                // Unique user ID
	Name              string          `json:"name"`               // Full name
	Email             string          `json:"email"`              // Email address
	EmailVerified     bool            `json:"email_verified"`     // Whether email is verified
	PreferredUsername string          `json:"preferred_username"` // Username
	FederatedClaims   FederatedClaims `json:"federated_claims"`   // Federated claims
}

// FederatedClaims contains the user's identity and profile information from upstream IdP.
type FederatedClaims struct {
	Connector Connector `json:"connector_id"` // Which connector was used
	UserID    string    `json:"user_id"`      // Connector-specific user ID
}

// Payload contains the tokens and claims returned from Dex after exchanging the code.
type Payload struct {
	Token   *oauth2.Token // OAuth2 token
	IDToken *oidc.IDToken // ID token (JWT)
	Claims  *Claims       // Decoded user claims
}

// ExchangeCodeForToken exchanges the authorization code for tokens, verifies them,
// and returns the user's identity information.
func (dex *Dex) ExchangeCodeForToken(ctx context.Context, params *ExchangeRequest) (*Payload, error) {
	token, err := dex.oauth2cfg.Exchange(
		oidc.ClientContext(ctx, dex.c),
		params.Code, []oauth2.AuthCodeOption{oauth2.VerifierOption(string(params.Verifier))}...,
	)
	if err != nil {
		return nil, err
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("missing 'id_token' in token response")
	}
	idToken, err := dex.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify ID token: %v", err)
	}

	// Verify access token using access token hash.
	rawAccessToken, ok := token.Extra("access_token").(string)
	if !ok || rawAccessToken == "" {
		return nil, fmt.Errorf("missing 'access_token' in token response")
	}
	if err := idToken.VerifyAccessToken(rawAccessToken); err != nil {
		return nil, fmt.Errorf("verify access token: %v", err)
	}

	// Decode common user claims.
	var claims Claims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("parse claims: %v", err)
	}

	return &Payload{Token: token, IDToken: idToken, Claims: &claims}, nil
}
