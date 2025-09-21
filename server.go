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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cespedes/jambo/mergefs"
	"github.com/go-jose/go-jose/v4"
)

const _DEBUG = false

//go:embed web/static
var _webStatic embed.FS

//go:embed web/templates
var _webTemplates embed.FS

type Client struct {
	id                  string
	secret              string
	allowedRedirectURIs []string
	allowedScopes       []string // allowed extra scopes
	allowedRoles        []string // if empty, any user is allowed
}

type Connection struct {
	code        string
	client      *Client
	redirectURI string
	state       string
	nonce       string
	scopes      []string
	response    Response // last response from the authenticator
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

	sync.Mutex  // to access clients and connections
	clients     []*Client
	connections map[string]Connection
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

	if _DEBUG {
		fmt.Println("# Static files")
		fs.WalkDir(s.webStatic, ".", fs.WalkDirFunc(func(path string, d fs.DirEntry, err error) error {
			if d.IsDir() {
				fmt.Print("D")
			} else {
				fmt.Print("-")
			}
			fmt.Printf(" %s\n", path)
			return nil
		}))
	}

	s.webTemplates, err = template.ParseFS(_webTemplates, "web/templates/*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		return nil
	}

	if _DEBUG {
		fmt.Println("# Templates")
		for _, t := range s.webTemplates.Templates() {
			fmt.Printf("- %s\n", t.Name())
		}
	}

	s.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _DEBUG {
			log.Printf("%s %s\n", r.Method, r.URL)
		}
		s.mux.ServeHTTP(w, r)
	})

	s.routes()

	s.connections = make(map[string]Connection)

	// fmt.Printf("Server ready at %s (root path is %s).\n", issuer, root)
	return &s
}

func (s *Server) routes() {
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("/.well-known/openid-configuration", s.openIDConfiguration)
	s.mux.HandleFunc("/auth", s.openIDAuth)
	s.mux.HandleFunc("/auth/login", s.authLogin)
	s.mux.HandleFunc("/token", s.openIDToken)
	s.mux.HandleFunc("/keys", s.openIDKeys)

	// All the files and dirs inside s.webStatic will be served as-is:
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// no need to worry about ".." in path because we are looking inside a fs.FS
		path := strings.Trim(r.URL.Path, "/")
		if path == "" {
			path = "."
		}
		f, err := s.webStatic.Open(path)
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
			if f, err = s.webStatic.Open(index); err != nil {
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

// AddStaticFS adds the content of a filesystem (a [fs.FS]) to the list of static files
// served by a Server.
func (s *Server) AddStaticFS(filesystem fs.FS) {
	s.webStatic = mergefs.Merge(filesystem, s.webStatic)
	// fmt.Println("# New static files")
	// fs.WalkDir(s.webStatic, ".", fs.WalkDirFunc(func(path string, d fs.DirEntry, err error) error {
	// 	if d.IsDir() {
	// 		fmt.Print("D")
	// 	} else {
	// 		fmt.Print("-")
	// 	}
	// 	fmt.Printf(" %s\n", path)
	// 	return nil
	// }))
}

// AddTemplatesFS adds the files inside a [fs.FS] to the list of templates processed by a Server.
func (s *Server) AddTemplatesFS(filesystem fs.FS) error {
	var err error

	s.webTemplates, err = s.webTemplates.ParseFS(filesystem, "*")

	if err != nil {
		return err
	}

	if _DEBUG {
		fmt.Println("# New templates")
		for _, t := range s.webTemplates.Templates() {
			fmt.Printf("- %s\n", t.Name())
		}
	}

	return nil
}

func (s *Server) AddTemplateArg(key, value string) {
	if s.templateArgs == nil {
		s.templateArgs = make(map[string]string)
	}
	s.templateArgs[key] = value
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
	c := &Client{
		id:     name,
		secret: secret,
	}
	s.clients = append(s.clients, c)
	return c
}

func (c *Client) AddAllowedRedirectURIs(names ...string) {
	c.allowedRedirectURIs = append(c.allowedRedirectURIs, names...)
}

func (c *Client) AddAllowedScopes(names ...string) {
	c.allowedScopes = append(c.allowedScopes, names...)
}

// AddAllowedRoles adds one or more roles to the list of the
// allowed roles for users.  If there are no allowed roles, any user
// can log in.  If there is at least one, the users must belong to one
// of them.
func (c *Client) AddAllowedRoles(names ...string) {
	c.allowedRoles = append(c.allowedRoles, names...)
}

//	allowedScopes         []string // allowed extra scopes
//	allowedAuthenticators []string // if empty, any authenticator is allowed
//	allowedRoles          []string // if empty, any user is allowed
