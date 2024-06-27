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

	"github.com/otakakot/openid-connect/internal/token"
	"github.com/otakakot/openid-connect/pkg/api"
)

func main() {
	http.HandleFunc("/.well-known/openid-configuration", OpenIDConfiguration)

	http.HandleFunc("/authorize", Authorize)

	http.HandleFunc("/login", Login)

	http.HandleFunc("/callback", Callback)

	http.HandleFunc("/token", Token)

	workers.Serve(nil) // use http.DefaultServeMux
}

func OpenIDConfiguration(
	rw http.ResponseWriter,
	req *http.Request,
) {
	bt := bytes.Buffer{}

	issuer := req.URL.Scheme + "://" + req.Host

	conf := api.OpenIDConfigurationResponseSchema{
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + "/authorize",
		JwksUri:               issuer + "/certs",
		RevocationEndpoint:    issuer + "/revoke",
		TokenEndpoint:         issuer + "/token",
		UserinfoEndpoint:      issuer + "/userinfo",
	}

	if err := json.NewEncoder(&bt).Encode(conf); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	rw.Write(bt.Bytes())
}

const (
	sessionKVNS = "openid-connect-session"
	codeKVNS    = "openid-connect-code"
	userKVNS    = "openid-connect-user"
)

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
	sessionKV, err := cloudflare.NewKVNamespace(sessionKVNS)
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

	session := Session{
		ResponseType: rt,
		ClientID:     cid,
		RedirectURI:  red,
		Scope:        sc,
		State:        st,
	}

	sessionBuf := bytes.Buffer{}

	if err := json.NewEncoder(&sessionBuf).Encode(session); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	slog.Info(fmt.Sprintf("session: %+v", session))

	id := GenerateID(10)

	if err := sessionKV.PutString(id, base64.StdEncoding.EncodeToString(sessionBuf.Bytes()), nil); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	redirectBuf := bytes.Buffer{}

	redirectBuf.WriteString("/login")

	values := url.Values{
		"id": {id},
	}

	redirectBuf.WriteByte('?')

	redirectBuf.WriteString(values.Encode())

	redirect, _ := url.ParseRequestURI(redirectBuf.String())

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

type User struct {
	ID    string
	Email string
}

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
		userKV, err := cloudflare.NewKVNamespace(userKVNS)
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

		slog.Info(sid.Value)

		email := req.FormValue("email")

		pass := req.FormValue("password")

		slog.Info(email)

		slog.Info(pass)

		// TODO: validate email and password

		user := User{
			ID:    GenerateID(20),
			Email: req.FormValue("email"),
		}

		userBuf := bytes.Buffer{}

		if err := json.NewEncoder(&userBuf).Encode(user); err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		if err := userKV.PutString(sid.Value, base64.StdEncoding.EncodeToString(userBuf.Bytes()), nil); err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

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
	sessionKV, err := cloudflare.NewKVNamespace(sessionKVNS)
	if err != nil {
		slog.Error("error creating sessionKV namespace")
		slog.Error(err.Error())

		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	userKV, err := cloudflare.NewKVNamespace(userKVNS)
	if err != nil {
		slog.Error("error creating userKV namespace")
		slog.Error(err.Error())

		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	codeKV, err := cloudflare.NewKVNamespace(codeKVNS)
	if err != nil {
		slog.Error("error creating codeKV namespace")
		slog.Error(err.Error())

		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	sid, err := req.Cookie(session_key)
	if err != nil {
		// TODO: redirect
		http.Error(rw, err.Error(), http.StatusUnauthorized)

		return
	}

	sessionStr, err := sessionKV.GetString(sid.Value, nil)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusUnauthorized)

		return
	}

	if err := sessionKV.Delete(sid.Value); err != nil {
		slog.Error("error deleting session")
		slog.Error(err.Error())

		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	sessionBt, _ := base64.StdEncoding.DecodeString(sessionStr)

	session := Session{}

	if err := json.NewDecoder(bytes.NewReader(sessionBt)).Decode(&session); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	slog.Info(fmt.Sprintf("session: %+v", session))

	userStr, err := userKV.GetString(sid.Value, nil)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusUnauthorized)

		return
	}

	if err := userKV.Delete(sid.Value); err != nil {
		slog.Error("error deleting user")
		slog.Error(err.Error())

		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	code := GenerateID(15)

	if err := codeKV.PutString(code, userStr, nil); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	cookie := http.Cookie{
		Name:   session_key,
		Value:  "",
		MaxAge: -1,
	}

	http.SetCookie(rw, &cookie)

	redirectBuf := bytes.Buffer{}

	redirectBuf.WriteString(session.RedirectURI)

	values := url.Values{
		"code":  {code},
		"state": {session.State},
	}

	redirectBuf.WriteByte('?')

	redirectBuf.WriteString(values.Encode())

	http.Redirect(rw, req, redirectBuf.String(), http.StatusFound)
}

func Token(
	rw http.ResponseWriter,
	req *http.Request,
) {
	switch req.FormValue("grant_type") {
	case string(api.AuthorizationCode):
		codeKV, err := cloudflare.NewKVNamespace(codeKVNS)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		code := req.FormValue("code")

		slog.Info(code)

		userStr, err := codeKV.GetString(code, nil)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)

			return
		}

		userBt, _ := base64.StdEncoding.DecodeString(userStr)

		user := User{}

		if err := json.NewDecoder(bytes.NewReader(userBt)).Decode(&user); err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		slog.Info(fmt.Sprintf("user: %+v", user))

		red := req.FormValue("redirect_uri")

		slog.Info(red)

		cid := req.FormValue("client_id")

		slog.Info(cid)

		csec := req.FormValue("client_secret")

		slog.Info(csec)

		scope := req.FormValue("scope")

		slog.Info(scope)

		// FIXME
		sign := "secret"

		iss := req.URL.Scheme + "://" + req.Host

		at := token.GenerateAccessToken(iss, user.ID)

		it := token.GenerateIDToken(iss, user.ID, cid, "")

		// FIXME generate refresh token
		rt := "refresh_token"

		key := token.GenerateSignKey()

		res := api.TokenResponseSchema{
			AccessToken:  at.JWT(sign),
			ExpiresIn:    3600,
			IdToken:      it.JWT(key),
			RefreshToken: rt,
			TokenType:    "Bearer",
		}

		bt := bytes.Buffer{}

		if err := json.NewEncoder(&bt).Encode(res); err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		rw.Write(bt.Bytes())
	case string(api.RefreshToken):
		panic("Not Implemented")
	default:
		http.Error(rw, "Unsupported grant_type", http.StatusBadRequest)

		return
	}
}
