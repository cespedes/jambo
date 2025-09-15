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

	s.SetAuthenticator(func (req *jambo.Request) *jambo.Response {
		if req.Params["login"] == "admin" && req.Params["pass"] == "secret" {
			return jambo.Response{
                Type: jambo.ResponseTypeLoginOK,
                Claims: map[string]any {
                    "login": "admin",
                    "name": "Charlie Root",
                },
            }
		}
		return jambo.Response{
            Type: jambo.ResponseTypeLoginFailed,
        }
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

# HTTP server endpoints

| endpoint                            | description
|-------------------------------------|------------------------------------------------------------|
| `/.well-known/openid-configuration` | OpenID Connect configuration                               |
| `/auth`                             | HTML page to ask for credentials                           |
| `POST /auth/request`                | to send login information (password, OTP...) to the server |
| `POST /token`                       | used by clients to send the _code_ and get _access token_  |
| `/keys`                             | get the list of keys used to sign the tokens               |

# Workflow

We will assume Alice (client) wants to connect to a GitLab instance (client),
which is configured to authenticate using Jambo, our OpenID Connect provider.

- Alice opens a web browser and goes to GitLab page (https://gitlab.example.com).
- GitLab redirects to Jambo's authentication page (https://jambo.example.com/auth),
  with query parameters specifying the client (GitLab) and the list of the required scopes.
- Jambo reads the query parameters and checks if the client exists and the URL is well-formed.
- Jambo creates a session for this connection and stores its state.
- Jambo parses a HTML template and offers it to Alice a login page (typically with a HTML form).
- Alice fills the user and password and presses "submit".
- The form is posted to the authentication page (https://jambo.example.com/auth/request).
- Jambo receives the request, checks if it somes from an active session, and calls the
  Authenticator function with all the parameters received from the form.
- The Authentication function checks the parameters and returns a "Login OK".
- Jambo optionally redirects to an approval HTML template, with a summary and a way to
  continue to the client (GitLab).
- When Alice clicks "OK", Jambo redirects to the GitLab's "callback address"
- GitLab receives the request with a "code"
- GitLab connects to Jambo in background, sending the "code" and the "client secret".
- Jambo replies with an _access token_ which contains a BASE64 signed JSON object with the
  claims (login, name, e-mail...) depending on the requested scopes.
- GitLab receives the response and sends Alice the GitLab page, already authenticated.

# Other OpenID Connect providers

- https://github.com/ory/hydra
- https://github.com/dexidp/dex
- https://github.com/zitadel/zitadel
- https://github.com/keycloak/keycloak (written in Java)
- https://github.com/goauthentik/authentik (Python / Javascript)
