package jambo

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/go-jose/go-jose/v4"
)

type Server struct {
	root   string
	issuer string
	mux    http.Handler

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

	mux := http.NewServeMux()
	s.mux = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %v\n", r.Method, r.URL, r)
		mux.ServeHTTP(w, r)
	})

	fmt.Printf("config is at %q.\n", root+"/.well-known/openid-configuration")
	mux.HandleFunc(root+"/.well-known/openid-configuration", s.openIDConfiguration)
	mux.HandleFunc(root+"/auth", s.openIDAuth)
	mux.HandleFunc(root+"/token", s.openIDToken)
	mux.HandleFunc(root+"/keys", s.openIDKeys)
	return &s
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

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) SetAuthenticator(f func(string, string) bool) {
	s.authenticator = f
}
