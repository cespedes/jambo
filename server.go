package jambo

import (
	"fmt"
	"net/http"
)

type Server struct {
	root   string
	issuer string
	mux    *http.ServeMux
}

func NewServer(issuer, root string) *Server {
	var s Server
	s.root = root
	s.issuer = issuer
	s.mux = http.NewServeMux()
	fmt.Printf("config is at %q.\n", root+"/.well-known/openid-configuration")
	s.mux.HandleFunc(root+"/.well-known/openid-configuration", s.openIDConfiguration)
	return &s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}
