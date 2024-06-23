//go:build js && wasm
// +build js,wasm

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"

	"github.com/syumai/workers"
	"github.com/syumai/workers/cloudflare"

	"github.com/otakakot/openid-connect/pkg/api"
)

func main() {
	http.HandleFunc("/.well-known/openid-configuration", OpenIDConfiguration)

	http.HandleFunc("/authorize", Authorize)

	http.HandleFunc("/login", Login)

	http.HandleFunc("/callback", Callback)

	workers.Serve(nil) // use http.DefaultServeMux
}

func OpenIDConfiguration(
	rw http.ResponseWriter,
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
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	rw.Write(bt.Bytes())
}

const namespace = "openid-connect"

type Session struct {
	ResponseType string
	ClientID     string
	RedirectURI  string
	Scope        string
	State        string
}

func Authorize(
	rw http.ResponseWriter,
	req *http.Request,
) {
	kv, err := cloudflare.NewKVNamespace(namespace)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	rt := req.URL.Query().Get("response_type")

	slog.Info(rt)

	// TODO: validate response_type

	cid := req.URL.Query().Get("client_id")

	slog.Info(cid)

	// TODO: validate client_id

	red := req.URL.Query().Get("redirect_uri")

	slog.Info(red)

	// TODO: validate redirect_uri

	sc := req.URL.Query().Get("scope")

	slog.Info(sc)

	// TODO: validate scope

	st := req.URL.Query().Get("state")

	slog.Info(st)

	// TODO: validate state

	ss := Session{
		ResponseType: "rt",
		ClientID:     "cid",
		RedirectURI:  "https://example.com",
		Scope:        "sc",
		State:        "st",
	}

	bt := bytes.Buffer{}

	if err := json.NewEncoder(&bt).Encode(ss); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	buf := bytes.Buffer{}

	buf.WriteString("/login")

	id := GenerateID(10)

	if err := kv.PutString(id, base64.StdEncoding.EncodeToString(bt.Bytes()), nil); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	values := url.Values{
		"id": {id},
	}

	buf.WriteByte('?')

	buf.WriteString(values.Encode())

	redirect, _ := url.ParseRequestURI(buf.String())

	http.Redirect(rw, req, redirect.String(), http.StatusFound)
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func GenerateID(length int) string {
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

const session_key = "__session__"

func Login(
	rw http.ResponseWriter,
	req *http.Request,
) {
	switch req.Method {
	case http.MethodGet:
		id := req.URL.Query().Get("id")

		cookie := http.Cookie{
			Name:     session_key,
			Value:    id,
			HttpOnly: true,
		}

		http.SetCookie(rw, &cookie)

		rw.Write([]byte(view))

		return
	case http.MethodPost:
		sid, err := req.Cookie(session_key)
		if err != nil {
			// TODO: redirect
			http.Error(rw, err.Error(), http.StatusUnauthorized)

			return
		}

		slog.Info(sid.Value)

		slog.Info(req.FormValue("email"))

		slog.Info(req.FormValue("password"))

		http.Redirect(rw, req, "/callback", http.StatusFound)
	default:
		http.Error(rw, "Method Not Allowed", http.StatusMethodNotAllowed)

		return

	}
}

const view = `<!DOCTYPE html>
<html lang="en">

<head>
    <title>Login</title>
</head>

<body>
    <form method="POST" action="/login">
        <label for="email">Email</label>
        <input type="email" name="email" id="email">

        <label for="password">Password</label>
        <input type="password" name="password" id="password">

        <button type="submit">Login</button>
    </form>
</body>

</html>
`

func Callback(
	rw http.ResponseWriter,
	req *http.Request,
) {
	kv, err := cloudflare.NewKVNamespace(namespace)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	sid, err := req.Cookie(session_key)
	if err != nil {
		// TODO: redirect
		http.Error(rw, err.Error(), http.StatusUnauthorized)

		return
	}

	state, err := kv.GetString(sid.Value, nil)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusUnauthorized)

		return
	}

	if err := kv.Delete(sid.Value); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	slog.Info(state)

	bt, _ := base64.StdEncoding.DecodeString(state)

	ss := Session{}

	if err := json.NewDecoder(bytes.NewReader(bt)).Decode(&ss); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	cookie := http.Cookie{
		Name:   session_key,
		Value:  "",
		MaxAge: -1,
	}

	slog.Info(fmt.Sprintf("session: %+v", ss))

	http.SetCookie(rw, &cookie)

	http.Redirect(rw, req, ss.RedirectURI, http.StatusFound)
}
