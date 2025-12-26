package frontdex

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/tetsuo/frontdex/dex"
)

// handleRedirect initiates the authentication process. It generates a random state,
// nonce, and PKCE verifier, constructs an authorization URL for the specified connector,
// and returns the URL along with an encrypted token representing the login session.
func (fdx *frontdex) handleRedirect(r *http.Request) (string, []byte, error) {
	via := Connector(r.FormValue(fdx.opts.ConnectorFieldName))
	if _, found := fdx.opts.Connectors[via]; !found {
		return "", nil, ErrBadConnector
	}

	token := make([]byte, verifierEnd) // state | nonce | verifier
	if err := randRead(token); err != nil {
		return "", nil, fmt.Errorf("build token: %v", err)
	}

	verifier := token[nonceEnd:verifierEnd]
	verifierHash := sha256.Sum256(verifier)
	codeChallenge := base64.RawURLEncoding.EncodeToString(verifierHash[:])

	authReq := &dex.AuthRequest{
		State:         string(token[:stateEnd]),
		Nonce:         string(token[stateEnd:nonceEnd]),
		CodeChallenge: codeChallenge,
		ClientIP:      fdx.opts.RealIP.FromRequest(r),
		Via:           via,
	}

	url, err := fdx.dex.GetAuthorizationURL(r.Context(), authReq)
	if err != nil {
		return "", nil, err
	}

	ciphertext, err := fdx.cyp.Encrypt(token)
	if err != nil {
		return "", nil, fmt.Errorf("encrypt state: %v", err)
	}

	return url, ciphertext, nil
}

func randRead(b []byte) error {
	if _, err := rand.Read(b); err != nil {
		return err
	}
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for i, x := range b {
		// Use byte modulo 64 (x & 63) for uniform distribution of characters
		b[i] = charset[x&63]
	}
	return nil
}
