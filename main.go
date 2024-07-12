package main

import (
	"net/http"

	"github.com/syumai/workers"

	"github.com/otakakot/openid-connect/internal/handler"
)

func main() {
	http.HandleFunc("/.well-known/openid-configuration", handler.OpenIDConfiguration) // OIDC

	http.HandleFunc("/authorize", handler.Authorize) // OIDC

	http.HandleFunc("/login", handler.Login) // IdP

	http.HandleFunc("/callback", handler.Callback) // IdP

	http.HandleFunc("/token", handler.Token) // OIDC

	http.HandleFunc("/userinfo", handler.UserInfo) // OIDC

	http.HandleFunc("/certs", handler.Certs) // OIDC

	http.HandleFunc("/revoke", handler.Revoke) // OIDC

	workers.Serve(nil) // use http.DefaultServeMux
}
