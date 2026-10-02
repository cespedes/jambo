package main

import (
	"flag"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cespedes/jambo"
)

func main() {
	err := run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	var issuer string

	flags := flag.NewFlagSet(args[0], flag.ExitOnError)

	flags.StringVar(&issuer, "issuer", "http://127.0.0.1:7480/oidc", "URL of the OpenID Connect issuer.")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}

	// The server is mounted under the path of the issuer URL.
	u, err := url.Parse(issuer)
	if err != nil {
		return err
	}
	root := strings.TrimSuffix(u.Path, "/")
	listenAddr := "127.0.0.1:7480"
	s := jambo.NewServer(issuer, root)

	clientID := "test-client"
	clientSecret := "client-secret"
	client := s.NewClient(clientID, clientSecret)
	client.AddAllowedRedirectURIs("http://127.0.0.1:5555/callback")

	s.SetAuthenticator(func(req *jambo.Request) jambo.Response {
		if req.Params["login"] == "admin" && req.Params["password"] == "secret" {
			return jambo.Response{
				Type:   jambo.ResponseTypeLoginOK,
				Login:  "admin",
				Name:   "Charlie Root",
				Claims: map[string]any{},
			}
		}
		return jambo.Response{
			Type:  jambo.ResponseTypeLoginFailed,
			Login: req.Params["login"],
		}
	})

	log.Printf("issuer=%q root=%q listenAddr=%q\n", issuer, root, listenAddr)
	server := &http.Server{
		Addr:              listenAddr,
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return server.ListenAndServe()
}
