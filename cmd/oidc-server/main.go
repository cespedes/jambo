package main

import (
	"flag"
	"log"
	"net/http"
	"os"

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

	root := "/oidc"
	listenAddr := ":7480"
	s := jambo.NewServer(issuer, root)

	/*
		clientID := "test-client"
		clientSecret := "client-secret"
		s.AddClient(clientID, clientSecret)

		s.SetAuthenticator(func(user, pass string) bool {
			return user == "admin" && pass == "secret"
		})
	*/

	log.Printf("issuer=%q root=%q listenAddr=%q\n", issuer, root, listenAddr)
	return http.ListenAndServe(listenAddr, s)
}
