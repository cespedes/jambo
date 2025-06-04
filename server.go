package jambo

import (
	"fmt"
	"log"
	"net/http"
)

type Server struct {
	root   string
	issuer string
	mux    http.Handler
}

func NewServer(issuer, root string) *Server {
	var s Server
	s.root = root
	s.issuer = issuer
	mux := http.NewServeMux()
	s.mux = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %v\n", r.Method, r.URL, r)
		mux.ServeHTTP(w, r)
	})

	fmt.Printf("config is at %q.\n", root+"/.well-known/openid-configuration")
	mux.HandleFunc(root+"/.well-known/openid-configuration", s.openIDConfiguration)
	return &s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}
