package dex

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"golang.org/x/net/html"
)

// CallbackRequest contains parameters for handling the OAuth2 callback from Dex.
type CallbackRequest struct {
	RawQuery string // Raw query string from the callback URL
	ClientIP string // Client IP address
}

// Callback handles the OAuth callback from the provider: it validates the callback URL,
// extracts the state and code, and returns them for further processing.
func (dex *Dex) Callback(ctx context.Context, params *CallbackRequest) (string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dex.callbackURL+params.RawQuery, nil)
	if err != nil {
		return "", "", err
	}

	if params.ClientIP != "" {
		req.Header.Set(dex.clientIPHeader, params.ClientIP)
	}

	res, err := dex.c.Do(req)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "", "", ErrTimeout
		}
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return "", "", fmt.Errorf("%w: %v", ErrNetwork, urlErr.Err)
		}
		return "", "", err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	// Expect 303 See Other for successful flow
	case http.StatusSeeOther:
		if locationURL := res.Header.Get("Location"); locationURL == "" {
			return "", "", fmt.Errorf("missing Location header in dex 303 response")
		} else {
			u, err := url.Parse(locationURL)
			if err != nil {
				return "", "", fmt.Errorf("failed to parse dex callback URL %q: %v", locationURL, err)
			}
			if baseURL := (u.Scheme + "://" + u.Host + u.Path); baseURL != dex.oauth2cfg.RedirectURL {
				return "", "", fmt.Errorf("expected callback URL %q, got %q", dex.oauth2cfg.RedirectURL, baseURL)
			}
			q := u.Query()
			return q.Get("state"), q.Get("code"), nil
		}
	case http.StatusBadRequest, http.StatusInternalServerError:
		n, err := html.Parse(res.Body)
		if err != nil {
			return "", "", fmt.Errorf("failed to parse dex %d error response: %v", res.StatusCode, err)
		}
		if err = parseErrorFromHTML(n); err == nil {
			return "", "", fmt.Errorf("dex returned %d, but no error information found in HTML", res.StatusCode)
		} else {
			return "", "", err
		}
	}

	return "", "", fmt.Errorf("dex returned unexpected status code: %d", res.StatusCode)
}
