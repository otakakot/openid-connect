package main

import (
	"net/http"

	"github.com/syumai/workers"

	"github.com/otakakot/openid-connect/internal/handler"
)

func main() {
	// OpenID Connect
	http.HandleFunc("GET /.well-known/openid-configuration", handler.OpenIDConfiguration)
	http.HandleFunc("GET /authorize", handler.Authorize)
	http.HandleFunc("POST /token", handler.Token)
	http.HandleFunc("GET /userinfo", handler.UserInfo)
	http.HandleFunc("POST /userinfo", handler.UserInfo)
	http.HandleFunc("GET /certs", handler.Certs)
	http.HandleFunc("POST /revoke", handler.Revoke)

	http.HandleFunc("/login", handler.Login)
	http.HandleFunc("/callback", handler.Callback)

	workers.Serve(nil) // use http.DefaultServeMux
}
