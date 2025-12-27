# frontdex

OAuth2/OpenID Connect middleware for Go that fronts [Dex](https://dexidp.io/)

[![Go Reference](https://pkg.go.dev/badge/github.com/tetsuo/frontdex.svg)](https://pkg.go.dev/github.com/tetsuo/frontdex)
[![Go Report Card](https://goreportcard.com/badge/github.com/tetsuo/frontdex)](https://goreportcard.com/report/github.com/tetsuo/frontdex)

frontdex provides authentication middleware that integrates with [Dex](https://dexidp.io/), an open-source OpenID Connect (OIDC) and OAuth 2.0 identity provider capable of authenticating users via various backends such as GitHub, Google, Microsoft, or LDAP.

Typically, applications either redirect users directly to Dex for login or place it behind a reverse proxy to control requests before they reach Dex (for example, as in [Argo CD](https://github.com/argoproj/argo-cd/blob/5cce5fe59b6350e4f4ad1971b6bf2fa925a1f792/util/dex/dex.go#L61)).

frontdex is intended for scenarios where you want to completely hide Dex from end users. It handles the [Authorization Code flow](https://oauth.net/2/grant-types/authorization-code/) (with [PKCE](https://oauth.net/2/pkce/)) on behalf of your application and stores a payload in the request context containing tokens and user info for further processing.

## Quickstart

### 1. Start Dex

Create a Dex config file `dex.yaml` like this:

```yaml
# The URL where your app is reachable, not Dex itself
issuer: http://localhost:8080/login

# See https://dexidp.io/docs/storage/ for other storage options
storage:
  type: memory

web:
  http: 0.0.0.0:5556 # Dex will listen on this port
  clientRemoteIP:
    header: X-Forwarded-For # frontdex sets this header

oauth2:
  grantTypes:
    - "authorization_code"
  responseTypes: [ "code" ]
  skipApprovalScreen: true # must be set

staticClients:
- id: example-client
  redirectURIs:
  - 'http://localhost:8080/login/callback'
  name: 'Example client'
  secret: change-me-in-production

# See https://dexidp.io/docs/connectors/ for other connectors
connectors:
- type: github
  id: github
  name: GitHub
  config:
    clientID: YOUR_OAUTH_CLIENT_ID
    clientSecret: YOUR_OAUTH_CLIENT_SECRET
    redirectURI: http://localhost:8080/login/callback # your OAuth app's callback URL
- type: mockCallback # for testing without external IdP
  id: mock
  name: Mock

logger:
  level: "debug"
  format: "text"
```

Here, we enable the [GitHub connector](https://dexidp.io/docs/connectors/github/) and a mock connector for testing. To use the GitHub connector, you need to [register a new OAuth app](https://github.com/settings/developers) on GitHub developer settings.

Start Dex with Docker:

```sh
docker run \
  --name dex \
  -p 5556:5556 \
  -v ./dex.yaml:/etc/dex/config.yaml \
  --rm \
  dexidp/dex:latest \
  dex serve /etc/dex/config.yaml
```

### 2. Create your app

Install:

```sh
go get github.com/tetsuo/frontdex
```

By default, frontdex fronts the Dex instance running at `localhost:5556`. You can configure it to point elsewhere using the `WithEndpointURL()` option.

> 📄 **See the API documentation at [pkg.go.dev](https://pkg.go.dev/github.com/tetsuo/frontdex) for all available options.**

There aren't many options to configure to test it out locally. Here's a minimal example app:

```go
package main

import (
	"encoding/json"
	"net/http"

	"github.com/tetsuo/frontdex"
)

func main() {
	fdx := frontdex.New(
		"http://localhost:8080/login",    // issuer URL
		"example-client",                 // client ID
		"change-me-in-production",        // client secret
		frontdex.WithCookieSecure(false), // for local testing
	)

	http.ListenAndServe(":8080", http.StripPrefix("/login", fdx(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if payload := frontdex.Payload(r); payload != nil {
				// User is logged in at /callback; payload contains the JWT and user info
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(payload)
			}
		}),
	)))
}
```

- Visit http://localhost:8080/login to start login.
- After login, user info will be available at /callback.
