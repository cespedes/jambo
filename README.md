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
	client := s.NewClient(clientID, clientSecret)
	client.AddAllowedRedirectURIs("https://example.com/callback")

	s.SetAuthenticator(func (req *jambo.Request) jambo.Response {
		if req.Params["login"] == "admin" && req.Params["password"] == "secret" {
			return jambo.Response{
				Type: jambo.ResponseTypeLoginOK,
				Login:  "admin",
				Name:   "Charlie Root",
				Claims: map[string]any{},
			}
		}
		return jambo.Response{
			Type: jambo.ResponseTypeLoginFailed,
			Login: req.Params["login"],
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
|-------------------------------------|------------------------------------------------------------------------------|
| `/.well-known/openid-configuration` | OpenID Connect configuration                                                 |
| `/auth`                             | HTML page to ask for credentials                                             |
| `POST /auth/login`                  | used by end users to send login information (password, OTP...) to the server |
| `POST /token`                       | used by clients to send the _code_ (or a _refresh token_) and get _id token_ and _access token_ |
| `/keys`                             | get the list of keys used to sign the tokens                                 |
| `/userinfo`                         | used by clients to get Claims from the access token                          |
| `/.well-known/ssf-configuration`    | Shared Signals Framework (SSF) transmitter configuration                     |
| `/ssf/stream`                       | SSF stream management: create/read/update/delete (POST/GET/PATCH/PUT/DELETE) |
| `/ssf/status`, `/ssf/subjects:add`, `/ssf/subjects:remove`, `/ssf/verify` | rest of the SSF stream management API |
| `POST /ssf/poll/{stream_id}`        | poll delivery: receivers pull pending Security Event Tokens from here        |

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
- Jambo receives the request, checks if it comes from an active session, and calls the
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

# Shared Signals Framework (SSF)

Jambo can also act as an SSF transmitter (OpenID Shared Signals Framework
1.0), so a receiver such as Apple Business Manager can subscribe to
security events (e.g. "a session was revoked") instead of, or in addition
to, doing SSO through it. This is what Apple Business Manager's
federated-authentication setup requires when it asks for an "SSF
configuration URL" and the `ssf.manage`/`ssf.read` scopes.

To wire it up:

```go
client := s.NewClient(clientID, clientSecret)
client.AddAllowedScopes("offline_access", "ssf.manage", "ssf.read")
client.AddSSFEventsSupported(jambo.EventCAEPSessionRevoked, jambo.EventCAEPCredentialChange)
```

- `offline_access` makes `/token` also return a refresh token, so the
  receiver can keep calling the SSF management API long after the user's
  session ends (a standard OAuth2 `grant_type=refresh_token` flow, not
  SSF-specific).
- `AddSSFEventsSupported` declares which event types this client's
  streams may ever receive; a receiver requests a subset of these when it
  creates a stream through the `/ssf/stream` management API.

The receiver creates and manages its own stream (delivered by push or
poll, its choice) using an OAuth access token obtained through the normal
authorization code flow. To actually notify it of something, call:

```go
s.EmitSecurityEvent(clientID, jambo.EventCAEPSessionRevoked, jambo.Subject{
	Format: jambo.SubjectFormatEmail,
	Email:  "alice@example.com",
}, nil)
```

which signs a Security Event Token and delivers it to every enabled
stream of that client that requested the event type and has that subject
registered.

**Trust model for `/ssf/subjects:add`:** a receiver registers which
subjects it wants events about itself, via its own `ssf.manage`-scoped
token -- Jambo does not check that the subject has ever actually
authenticated through that specific client, or has any other
relationship to it, before accepting the registration. Any client with
`ssf.manage` can therefore ask to be notified about any subject at all.
This is fine as long as `ssf.manage` is only ever granted, in the host
application's own client configuration, to receivers that are themselves
trusted with that scope of visibility (e.g. as of this writing, the only
place this is wired up grants it to a single, IT-managed client) --
but if a host application ever grants `ssf.manage` to more than one
client, each of those clients can silently monitor events for subjects
that have nothing to do with it. A host application that needs to
prevent that has to enforce it itself (e.g. by recording which subjects
have actually authenticated through a given client, and consulting that
before calling `EmitSecurityEvent` or before allowing `subjects:add` to
succeed for a subject outside that set) -- Jambo does not do this on its
own.

Refresh tokens and SSF streams (unlike the short-lived login state used
during SSO) are meant to outlive a process restart. Jambo keeps them in
memory by default (`MemoryStorage`), which is fine for development but
loses everything on restart; a production deployment should implement the
small [`Storage`](storage.go) interface against its own datastore and
install it with `Server.SetStorage` before serving traffic.

# Other OpenID Connect providers

- https://github.com/ory/hydra
- https://github.com/dexidp/dex
- https://github.com/zitadel/zitadel
- https://github.com/keycloak/keycloak (written in Java)
- https://github.com/goauthentik/authentik (Python / Javascript)
