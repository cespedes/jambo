package jambo

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"

	"github.com/go-jose/go-jose/v4"
)

func (s *Server) openIDKeys(w http.ResponseWriter, r *http.Request) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to generate RSA key: %v", err)
		http.Error(w, "Internal server error generating key.", http.StatusInternalServerError)
		return
	}
	b := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	keyID := hex.EncodeToString(b)

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       key.Public(),
			KeyID:     keyID,
			Algorithm: "RS256",
			Use:       "sig",
		}},
	}
	data, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		http.Error(w, "Internal server error marshaling keys.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
}
