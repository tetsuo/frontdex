package api

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

var (
	// ErrResourceUnavailable is returned when the requested state is not found on Dex.
	ErrResourceUnavailable = errors.New("requested resource does not exist")

	// ErrUserSession is returned when the state parameter is missing in the callback.
	ErrUserSession = errors.New("user session error")

	// ErrAuthFailure is returned when authentication fails (e.g., code is missing or invalid).
	ErrAuthFailure = errors.New("failed to authenticate")

	// ErrInvalidConnector indicates the connector in the request is invalid or not supported.
	ErrInvalidConnector = errors.New("connector invalid")
)

func parseErrorFromLocation(locationURL string) error {
	u, err := url.Parse(locationURL)
	if err != nil {
		return fmt.Errorf("failed to parse error location URL: %v", err)
	}
	query := u.Query()
	errorCode := query.Get("error")
	errorMessage := query.Get("error_description")
	if errorCode == "" {
		return nil
	}
	if errorMessage != "" {
		return fmt.Errorf("%s: %s", errorCode, errorMessage)
	}
	return fmt.Errorf("%s", errorCode)
}

// parseErrorFromHTML extracts error information from Dex's HTML error response.
func parseErrorFromHTML(n *html.Node) error {
	errorCode, errorMessage := extractErrorTitleAndDescription(n)
	if errorCode == "" {
		return nil
	}
	if errorMessage != "" {
		switch errorCode {
		case "Bad Request":
			switch errorMessage {
			case "Requested resource does not exist.":
				return ErrResourceUnavailable
			case "User session error.":
				return ErrUserSession
			case "Connector ID does not match a valid Connector":
				return ErrInvalidConnector
			}
		case "Internal Server Error":
			if strings.HasPrefix(errorMessage, "Failed to authenticate: ") {
				errorMessage = errorMessage[24:]
				if strings.HasPrefix(errorMessage, "google: ") {
					errorMessage = errorMessage[8:]
					if strings.HasPrefix(errorMessage, "failed to get token: oauth2: ") {
						errorMessage = errorMessage[29:]
						// code not present or invalid
						if strings.HasPrefix(errorMessage, "\"invalid_request\"") {
							return fmt.Errorf("%w: google: invalid request", ErrAuthFailure)
						}
						if strings.HasPrefix(errorMessage, "\"invalid_grant\" ") {
							return fmt.Errorf("%w: google: invalid grant", ErrAuthFailure)
						}
					}
				} else if strings.HasPrefix(errorMessage, "github: ") {
					errorMessage = errorMessage[8:]
					if strings.HasPrefix(errorMessage, "failed to get token: oauth2: ") {
						errorMessage = errorMessage[29:]
						// code not present/invalid or user email not verified
						if strings.HasPrefix(errorMessage, "\"bad_verification_code\"") {
							return fmt.Errorf("%w: github: bad verification code", ErrAuthFailure)
						}
						if strings.HasPrefix(errorMessage, "\"unverified_user_email\"") {
							return fmt.Errorf("%w: github: unverified user email", ErrAuthFailure)
						}
					}
				}
			}
		}
		return fmt.Errorf("%s: %s", errorCode, errorMessage)
	}
	return fmt.Errorf("%s", errorCode)
}

// extractErrorTitleAndDescription finds the first <div class="theme-panel"> and extracts <h2> and <p> from its direct children.
// WARNING: Do not change Dex's default error templates or the 'theme-panel' class, or error parsing will break.
func extractErrorTitleAndDescription(root *html.Node) (title, description string) {
	// Find <div class="theme-panel">
	var panel *html.Node
	for n := root; n != nil; {
		if n.Type == html.ElementNode && n.Data == "div" {
			for _, attr := range n.Attr {
				if attr.Key == "class" && attr.Val == "theme-panel" {
					panel = n
					break
				}
			}
			if panel != nil {
				break
			}
		}
		// Traverse: first child, else next sibling, else parent's next sibling
		if n.FirstChild != nil {
			n = n.FirstChild
		} else if n.NextSibling != nil {
			n = n.NextSibling
		} else {
			for n.Parent != nil {
				n = n.Parent
				if n.NextSibling != nil {
					n = n.NextSibling
					break
				}
			}
			if n.Parent == nil && n.NextSibling == nil {
				break
			}
		}
	}
	if panel == nil {
		return
	}
	// Extract <h2> and <p> from direct children of panel
	for c := panel.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.Data == "h2" && c.FirstChild != nil && title == "" {
			title = c.FirstChild.Data
		}
		if c.Type == html.ElementNode && c.Data == "p" && c.FirstChild != nil && description == "" {
			description = c.FirstChild.Data
		}
		if title != "" && description != "" {
			break
		}
	}
	return
}
