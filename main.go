package main

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/otakakot/openid-connect/pkg/api"
	"github.com/syumai/workers"
)

func main() {
	http.HandleFunc("/.well-known/openid-configuration", OpenIDConfiguration)

	workers.Serve(nil) // use http.DefaultServeMux
}

func OpenIDConfiguration(
	w http.ResponseWriter,
	req *http.Request,
) {
	bt := bytes.Buffer{}

	conf := api.OpenIDConfigurationResponseSchema{
		AuthorizationEndpoint: "dummy",
		Issuer:                "dummy",
		JwksUri:               "dummy",
		RevocationEndpoint:    "dummy",
		TokenEndpoint:         "dummy",
		UserinfoEndpoint:      "dummy",
	}

	if err := json.NewEncoder(&bt).Encode(conf); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(bt.Bytes())
}
