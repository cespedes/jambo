# jambo

jambo is an Go package to build an OpenID Connect provider (OIDC server).

"Jambo" is also a Swahili word.  It translates to "hello" or "hi".
It's a common greeting used in East Africa, particularly
in Tanzania and Kenya.

In order to create a OpenID Connect provider,
you will have to create a new server, which is
in turn a HTTP handler.

This is a complete example:

```go
package main

import (
	"github.com/cespedes/jambo"
)

func main() {
	issuer := "https://example.com/oidc"
	root := "/oidc"
	s := jambo.NewServer(issuer, root)

	clientID := "test-client"
	clientSecret := "client-secret"
	s.AddClient(clientID, clientSecret)

	s.SetCallback(func (user, pass string) bool {
		if req.User == "admin" && req.Password == "secret" {
			return jambo.Response{Type: jambo.ResponseTypeLoginOK}
		}
		return jambo.Response{Type: jambo.ResponseTypeLoginFailed}
	})

	http.ListenAndServe(":8080", s)
}
```

It will create a HTTP server, listening to requests under _root_
and providing all the necessary handlers for the OIDC provider.

---

The OpenID Connect specification is here:

- `https://openid.net/specs/openid-connect-discovery-1_0.html`
- `https://openid.net/specs/openid-connect-core-1_0.html`

# Other OpenID Connect providers

- https://github.com/ory/hydra
- https://github.com/dexidp/dex
- https://github.com/zitadel/zitadel
- https://github.com/keycloak/keycloak (written in Java)
- https://github.com/goauthentik/authentik (Python / Javascript)

# 2FA workflow

- User goes to (client-end-point)
- (client-end-point) redirects user to (issuer)/auth
- In that page, it asks for user and password
- jambo calls authenticate(user, password)
- If password is incorrect, inform and try again
- If password is correct and 2FA is not needed, authenticate and redirect to (client-callback)
- If password is correct and 2FA is needed, show 2FA options and let the user choose 1
- After choosing one, do some things (like sending an SMS)
  and ask for additional info (secret sent via SMS)
- If secret is correct, authenticate and proceed to (client-callback)
