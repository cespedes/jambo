package jambo

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cespedes/jambo/mergefs"
	"github.com/go-jose/go-jose/v4"
)

// connectionTTL is how long a pending connection (an in-progress
// authentication, identified by its code) is kept around before being
// considered expired and purged. This bounds the memory used by
// abandoned logins and by codes nobody ever redeemed.
const connectionTTL = 10 * time.Minute

//go:embed web/static
var _webStatic embed.FS

//go:embed web/templates
var _webTemplates embed.FS

type Client struct {
	id     string
	secret string

	// configMu guards the four fields below. It exists because a Client
	// returned by ReplaceClient is already reachable through s.clients --
	// and so through a live request -- before the caller finishes calling
	// AddAllowed*/AddSSFEventsSupported on it (see ReplaceClient's doc
	// comment); without it, that would race with, e.g., auth.go reading
	// allowedScopes to validate a concurrent /auth request.
	configMu            sync.RWMutex
	allowedRedirectURIs []string
	allowedScopes       []string // allowed extra scopes
	allowedRoles        []string // if empty, any user is allowed
	ssfEventsSupported  []string // Shared Signals Framework event type URIs this client's streams may receive
}

type Connection struct {
	code        string
	created     time.Time // used to expire stale, unredeemed connections
	client      *Client
	redirectURI string
	state       string
	nonce       string
	scopes      []string
	response    Response // last response from the authenticator

	// PKCE (RFC 7636), optional: set only if the client sent a
	// code_challenge to /auth. codeChallengeMethod is "S256" or "plain".
	codeChallenge       string
	codeChallengeMethod string
}

// expired reports whether conn is older than connectionTTL.
func (conn Connection) expired() bool {
	return time.Since(conn.created) > connectionTTL
}

// purgeExpiredConnections removes connections older than connectionTTL.
// Callers must hold s.Mutex.
func (s *Server) purgeExpiredConnections() {
	for code, conn := range s.connections {
		if conn.expired() {
			delete(s.connections, code)
		}
	}
}

type Server struct {
	// General configuration of server:
	root          string
	issuer        string
	handler       http.Handler
	authenticator func(*Request) Response

	// web pages:
	webStatic    fs.FS
	webTemplates *template.Template

	templateArgs map[string]string

	mux     *http.ServeMux
	key     jose.JSONWebKey
	allKeys jose.JSONWebKeySet

	debug bool // set via SetDebug; logs extra diagnostics when true

	storage              Storage // set via SetStorage; defaults to an in-memory Storage
	allowInsecureSSFPush bool    // set via SetSSFAllowPrivatePush; disables the SSRF guard on SSF push endpoint_url

	sync.Mutex  // to access clients, connections, and the webStatic/webTemplates/templateArgs presentation state
	clients     []*Client
	connections map[string]Connection
}

// SetDebug enables or disables extra diagnostic logging, such as
// incoming requests and the reasons behind auth/token errors. It can
// be called at any time and takes effect on the next log line.
func (s *Server) SetDebug(enabled bool) {
	s.debug = enabled
}

// SetStorage installs the Storage used to persist refresh tokens and SSF
// streams. It replaces the default MemoryStorage installed by NewServer.
// Call it before the Server starts handling requests.
func (s *Server) SetStorage(storage Storage) {
	s.storage = storage
}

// SetSSFAllowPrivatePush disables the SSRF guard that otherwise rejects
// SSF push delivery endpoint_url values resolving to loopback, private or
// link-local addresses, and the requirement that they use https. Only
// meant for local development and tests, where a receiver's push
// endpoint is legitimately something like http://127.0.0.1:port/.
func (s *Server) SetSSFAllowPrivatePush(allow bool) {
	s.allowInsecureSSFPush = allow
}

// clientByID returns the registered Client with the given id, or nil if none matches.
func (s *Server) clientByID(id string) *Client {
	s.Lock()
	defer s.Unlock()
	return s.clientByIDLocked(id)
}

// clientByIDLocked is clientByID for callers that already hold s.Mutex.
func (s *Server) clientByIDLocked(id string) *Client {
	for _, c := range s.clients {
		if c.id == id {
			return c
		}
	}
	return nil
}

// removeClientLocked removes the client with the given id from s.clients,
// if any. The caller must hold s.Mutex.
func (s *Server) removeClientLocked(id string) bool {
	for i, c := range s.clients {
		if c.id == id {
			s.clients = append(s.clients[:i], s.clients[i+1:]...)
			return true
		}
	}
	return false
}

func NewServer(issuer, root string) *Server {
	var err error

	var s Server
	s.root = root
	s.issuer = issuer

	err = s.createKey()
	if err != nil {
		log.Fatal(err)
	}

	if s.webStatic, err = fs.Sub(_webStatic, "web/static"); err != nil {
		// This should never return an error
		log.Fatal(err)
	}

	s.webTemplates, err = template.ParseFS(_webTemplates, "web/templates/*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		return nil
	}

	s.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.debug {
			log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		}
		s.mux.ServeHTTP(w, r)
	})

	s.routes()

	s.connections = make(map[string]Connection)
	s.storage = NewMemoryStorage()

	// fmt.Printf("Server ready at %s (root path is %s).\n", issuer, root)
	return &s
}

func (s *Server) routes() {
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("/.well-known/openid-configuration", s.openIDConfiguration)
	s.mux.HandleFunc("/auth", s.openIDAuth)
	s.mux.HandleFunc("/auth/login", s.authLogin)
	s.mux.HandleFunc("/token", s.openIDToken)
	s.mux.HandleFunc("/userinfo", s.userinfo)
	s.mux.HandleFunc("/keys", s.openIDKeys)

	// Shared Signals Framework (SSF): transmitter discovery, stream
	// management API and poll delivery. See ssf.go, ssf_stream.go and
	// ssf_event.go.
	s.mux.HandleFunc("/.well-known/ssf-configuration", s.ssfConfigurationHandler)
	s.mux.HandleFunc("POST /ssf/stream", s.ssfCreateStream)
	s.mux.HandleFunc("GET /ssf/stream", s.ssfGetStream)
	s.mux.HandleFunc("PATCH /ssf/stream", s.ssfUpdateStream)
	s.mux.HandleFunc("PUT /ssf/stream", s.ssfReplaceStream)
	s.mux.HandleFunc("DELETE /ssf/stream", s.ssfDeleteStream)
	s.mux.HandleFunc("GET /ssf/status", s.ssfGetStatus)
	s.mux.HandleFunc("POST /ssf/status", s.ssfSetStatus)
	s.mux.HandleFunc("POST /ssf/subjects:add", s.ssfAddSubject)
	s.mux.HandleFunc("POST /ssf/subjects:remove", s.ssfRemoveSubject)
	s.mux.HandleFunc("POST /ssf/verify", s.ssfVerify)
	s.mux.HandleFunc("POST /ssf/poll/{stream_id}", s.ssfPoll)

	// All the files and dirs inside s.webStatic will be served as-is:
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Snapshot s.webStatic under the lock: ReplacePresentation always
		// swaps in a brand new fs.FS rather than mutating this one in
		// place, so using this local copy for the rest of the request,
		// unlocked, is safe even if a reload happens concurrently.
		s.Lock()
		webStatic := s.webStatic
		s.Unlock()

		// no need to worry about ".." in path because we are looking inside a fs.FS
		path := strings.Trim(r.URL.Path, "/")
		if path == "" {
			path = "."
		}
		f, err := webStatic.Open(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		fi, err := f.Stat()
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if fi.IsDir() {
			index := filepath.Join(path, "index.html")
			f.Close()
			if f, err = webStatic.Open(index); err != nil {
				http.NotFound(w, r)
				return
			}
			if fi, err = f.Stat(); err != nil || fi.IsDir() {
				http.NotFound(w, r)
			}
		}
		http.ServeContent(w, r, fi.Name(), fi.ModTime(), f.(io.ReadSeeker))
	})
}

// ReplacePresentation resets the Server's static files, HTML templates
// and template arguments to a fresh copy of jambo's embedded defaults,
// then layers staticFS and templatesFS on top of them (either may be nil
// to mean "just the embedded defaults, no override"), and replaces
// templateArgs outright -- it is not merged with whatever was set
// before.
//
// It always builds the new state from scratch -- a fresh
// *template.Template is parsed rather than reusing and mutating the
// existing one -- before atomically swapping it in, which is what makes
// it safe to call on a Server that's already serving live traffic (e.g.
// to apply web_static/web_templates/template args from a reloaded
// configuration, on SIGHUP): a request being handled concurrently sees
// either the old presentation or the new one, never a torn mix of both.
//
// Client configuration (Server.clients) is untouched; see
// [Server.ReplaceClient] for that.
func (s *Server) ReplacePresentation(staticFS, templatesFS fs.FS, templateArgs map[string]string) error {
	newStatic, err := fs.Sub(_webStatic, "web/static")
	if err != nil {
		// Unreachable in practice: this is the same call NewServer makes,
		// over an embed.FS baked into the binary.
		return fmt.Errorf("embedded web/static: %w", err)
	}
	if staticFS != nil {
		newStatic = mergefs.Merge(staticFS, newStatic)
	}

	newTemplates, err := template.ParseFS(_webTemplates, "web/templates/*")
	if err != nil {
		// Also unreachable in practice; see above.
		return fmt.Errorf("embedded web/templates: %w", err)
	}
	if templatesFS != nil {
		if newTemplates, err = newTemplates.ParseFS(templatesFS, "*"); err != nil {
			return err
		}
	}

	newArgs := maps.Clone(templateArgs)

	s.Lock()
	defer s.Unlock()
	s.webStatic = newStatic
	s.webTemplates = newTemplates
	s.templateArgs = newArgs
	return nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sp := http.StripPrefix(s.root, s.handler)
	sp.ServeHTTP(w, r)
	// s.handler.ServeHTTP(w, r)
}

func (s *Server) createKey() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	b := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	keyID := hex.EncodeToString(b)

	s.key = jose.JSONWebKey{
		Key:       key,
		KeyID:     keyID,
		Algorithm: "RS256",
		Use:       "sig",
	}

	s.allKeys = jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       key.Public(),
			KeyID:     keyID,
			Algorithm: "RS256",
			Use:       "sig",
		}},
	}
	return nil
}

func (s *Server) SetAuthenticator(f func(req *Request) Response) {
	s.authenticator = f
}

type contextKey struct{}

// SetConnection stores a Connection in a http.Request
func (s *Server) SetConnection(r *http.Request, conn *Connection) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), contextKey{}, conn))
}

// SetConnection gets a Connection previously stored in a http.Request
func (s *Server) GetConnection(r *http.Request) *Connection {
	c, _ := r.Context().Value(contextKey{}).(*Connection)
	return c
}

func (s *Server) NewClient(name, secret string) *Client {
	s.Lock()
	defer s.Unlock()
	c := &Client{
		id:     name,
		secret: secret,
	}
	s.clients = append(s.clients, c)
	return c
}

// RemoveClient removes a previously registered client, so it can no
// longer authenticate, be looked up by /auth or /token, or call the SSF
// management API, and deletes that client id's refresh tokens and SSF
// streams from Storage. It returns false if no client with that id was
// registered (Storage is not touched in that case).
//
// It is safe to call while the Server is serving requests (e.g. to apply
// a reloaded configuration without restarting), but it does not reach
// into anything already in flight: an in-progress Connection (a pending
// /auth/login) keeps its own pointer to the Client it started with and
// is unaffected, and neither are already-issued access/ID tokens -- they
// simply stop working the next time something needs to look the client
// up again (redeeming a code or refresh token, or calling an SSF
// endpoint). The Storage deletion is best-effort: a failure is logged
// when SetDebug(true) is in effect but otherwise not surfaced, since
// RemoveClient's own bool return has no room for a second error.
//
// This is a hard delete precisely so that a client id can be reused
// later (e.g. NewClient after RemoveClient, for an unrelated client)
// without inheriting whatever the previous occupant of that id left
// behind. A host that instead wants to reconfigure the *same* client --
// keeping its refresh tokens and SSF streams -- should call
// ReplaceClient, not RemoveClient followed by NewClient.
func (s *Server) RemoveClient(id string) bool {
	s.Lock()
	removed := s.removeClientLocked(id)
	s.Unlock()
	if !removed {
		return false
	}

	if err := s.storage.DeleteRefreshTokensForClient(id); err != nil && s.debug {
		log.Printf("RemoveClient(%q): deleting refresh tokens: %v\n", id, err)
	}
	streams, err := s.storage.ListStreams(id)
	if err != nil {
		if s.debug {
			log.Printf("RemoveClient(%q): listing SSF streams: %v\n", id, err)
		}
		return true
	}
	for _, stream := range streams {
		if err := s.storage.DeleteStream(stream.StreamID); err != nil && s.debug {
			log.Printf("RemoveClient(%q): deleting SSF stream %s: %v\n", id, stream.StreamID, err)
		}
	}
	return true
}

// ReplaceClient atomically removes any existing client registered under
// id and registers a fresh one in its place, exactly as NewClient would
// if none existed. Use it to apply a changed configuration -- a
// different secret, redirect URIs, scopes, roles or SSF events -- to a
// client id without restarting the Server: the caller still needs to
// call AddAllowedRedirectURIs and any other AddAllowed*/
// AddSSFEventsSupported on the returned Client, exactly as after
// NewClient, since none of the old Client's configuration carries over.
//
// Unlike RemoveClient, ReplaceClient does not touch that client id's
// state in Storage (refresh tokens, SSF streams): it stays there,
// keyed by the client id string rather than by the *Client value, and
// remains reachable through the new Client -- e.g. a receiver's existing
// SSF stream survives its client's redirect_uri or scopes being edited
// and reloaded. Only use ReplaceClient to reconfigure what is still
// conceptually the same client; to repurpose an id for an unrelated one,
// call RemoveClient (which does delete that state) and then NewClient.
func (s *Server) ReplaceClient(id, secret string) *Client {
	s.Lock()
	defer s.Unlock()
	s.removeClientLocked(id)
	c := &Client{id: id, secret: secret}
	s.clients = append(s.clients, c)
	return c
}

func (c *Client) AddAllowedRedirectURIs(names ...string) {
	c.configMu.Lock()
	defer c.configMu.Unlock()
	c.allowedRedirectURIs = append(c.allowedRedirectURIs, names...)
}

// hasAllowedRedirectURI reports whether uri is one of c's allowed redirect URIs.
func (c *Client) hasAllowedRedirectURI(uri string) bool {
	c.configMu.RLock()
	defer c.configMu.RUnlock()
	return slices.Contains(c.allowedRedirectURIs, uri)
}

func (c *Client) AddAllowedScopes(names ...string) {
	c.configMu.Lock()
	defer c.configMu.Unlock()
	c.allowedScopes = append(c.allowedScopes, names...)
}

// hasAllowedScope reports whether scope is one of c's allowed extra scopes.
func (c *Client) hasAllowedScope(scope string) bool {
	c.configMu.RLock()
	defer c.configMu.RUnlock()
	return slices.Contains(c.allowedScopes, scope)
}

// AddAllowedRoles adds one or more roles to the list of the
// allowed roles for users.  If there are no allowed roles, any user
// can log in.  If there is at least one, the users must belong to one
// of them.
func (c *Client) AddAllowedRoles(names ...string) {
	c.configMu.Lock()
	defer c.configMu.Unlock()
	c.allowedRoles = append(c.allowedRoles, names...)
}

// allowedRolesSnapshot returns a copy of c's allowed roles, safe to keep
// and use after this call returns even if c's configuration changes later.
func (c *Client) allowedRolesSnapshot() []string {
	c.configMu.RLock()
	defer c.configMu.RUnlock()
	return slices.Clone(c.allowedRoles)
}

//	allowedScopes         []string // allowed extra scopes
//	allowedAuthenticators []string // if empty, any authenticator is allowed
//	allowedRoles          []string // if empty, any user is allowed
