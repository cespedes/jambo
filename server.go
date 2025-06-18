package jambo

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"embed"
	_ "embed"
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

	"github.com/go-jose/go-jose/v4"
)

//go:embed web/static
var _webStatic embed.FS

//go:embed web/templates
var _webTemplates embed.FS

type Client struct {
	ID           string
	Secret       string
	RedirectURIs []string
}

type Server struct {
	root    string
	issuer  string
	handler http.Handler
	mux     *http.ServeMux

	key     jose.JSONWebKey
	allKeys jose.JSONWebKeySet

	authenticator func(*Request) Response

	webStatic    fs.FS
	webTemplates *template.Template
	clients      []Client
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

	s.webStatic = _webStatic

	// fmt.Println("# Static files")
	// err = fs.WalkDir(s.webStatic, ".", fs.WalkDirFunc(func(path string, d fs.DirEntry, err error) error {
	// 	fmt.Printf("%v\n", d)
	// 	return nil
	// }))

	s.webTemplates, err = template.ParseFS(_webTemplates, "web/templates/*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		return nil
	}

	// fmt.Println("# Templates")
	// for _, t := range s.webTemplates.Templates() {
	// 	fmt.Printf("- %s\n", t.Name())
	// }

	s.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %v\n", r.Method, r.URL, r)
		s.mux.ServeHTTP(w, r)
	})

	s.routes()

	fmt.Printf("Server ready at %s (root path is %s).\n", issuer, root)
	return &s
}

func (s *Server) routes() {
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("/.well-known/openid-configuration", s.openIDConfiguration)
	s.mux.HandleFunc("/auth", s.openIDAuth)
	s.mux.HandleFunc("/token", s.openIDToken)
	s.mux.HandleFunc("/keys", s.openIDKeys)

	// All the files and dirs inside "web/static" will be served as-is:
	if fsys, err := fs.Sub(s.webStatic, "web/static"); err == nil {
		// s.mux.Handle("/", http.FileServerFS(fsys))
		s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			// no need to worry about ".." in path because we are looking inside a fs.FS
			path := strings.Trim(r.URL.Path, "/")
			if path == "" {
				path = "."
			}
			f, err := fsys.Open(path)
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
				if f, err = fsys.Open(index); err != nil {
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
		return nil
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

// AddClient adds a new client to the server.
// It cannot be used concurrently with any other access to Server.
func (s *Server) AddClient(clientID, clientSecret string, redirectURIs []string) {
	s.clients = append(s.clients, Client{
		ID:           clientID,
		Secret:       clientSecret,
		RedirectURIs: redirectURIs,
	})
}

type contextClient struct{}

func (s *Server) SetClient(r *http.Request, client *Client) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), contextClient{}, client))
}

func (s *Server) GetClient(r *http.Request) *Client {
	c, _ := r.Context().Value(contextClient{}).(*Client)
	return c
}
