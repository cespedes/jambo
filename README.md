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

	s.SetAuthenticator(func (user, pass string) bool {
		return user=="admin" && pass=="secret"
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
