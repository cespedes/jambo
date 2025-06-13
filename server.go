package jambo

import (
	"crypto/rand"
	"crypto/rsa"
	"embed"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

//go:embed web/static
var webStatic embed.FS

//go:embed web/templates
var webTemplates embed.FS

type Server struct {
	root    string
	issuer  string
	handler http.Handler
	mux     *http.ServeMux

	key     jose.JSONWebKey
	allKeys jose.JSONWebKeySet

	authenticator func(string, string) bool
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

	err = fs.WalkDir(webStatic, ".", fs.WalkDirFunc(func(path string, d fs.DirEntry, err error) error {
		fmt.Printf("path=%s d=%v err=%v\n", path, d, err)
		return nil
	}))
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
	if fsys, err := fs.Sub(webStatic, "web/static"); err == nil {
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

func (s *Server) SetAuthenticator(f func(string, string) bool) {
	s.authenticator = f
}
