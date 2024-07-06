package main

import (
	"bytes"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"strings"

	"github.com/syumai/workers"
	"github.com/syumai/workers/cloudflare"
	_ "github.com/syumai/workers/cloudflare/d1"

	"github.com/otakakot/openid-connect/internal/token"
	"github.com/otakakot/openid-connect/pkg/api"
	"github.com/otakakot/openid-connect/pkg/schema"
)

func main() {
	http.HandleFunc("/.well-known/openid-configuration", OpenIDConfiguration)

	http.HandleFunc("/authorize", Authorize)

	http.HandleFunc("/login", Login)

	http.HandleFunc("/callback", Callback)

	http.HandleFunc("/token", Token)

	http.HandleFunc("/userinfo", UserInfo)

	http.HandleFunc("/certs", Certs)

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

	// db, err := sql.Open("d1", "DB")
	// if err != nil {
	// 	http.Error(rw, err.Error(), http.StatusInternalServerError)

	// 	slog.Error("error opening database")

	// 	return
	// }

	// queries := schema.New(db)

	// cli, err := queries.FindClientByID(req.Context(), cid)
	// if err != nil {
	// 	http.Error(rw, err.Error(), http.StatusInternalServerError)

	// 	slog.Error("error finding client")

	// 	return
	// }

	// slog.Info(cli.ID)

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

		// FIXME
		key := token.GenerateSignKey()

		res := api.TokenResponseSchema{
			AccessToken:  at.JWT(sign),
			ExpiresIn:    3600,
			IdToken:      it.JWT(key),
			RefreshToken: rt,
			TokenType:    "Bearer",
		}

		buf := bytes.Buffer{}

		if err := json.NewEncoder(&buf).Encode(res); err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		rw.Write(buf.Bytes())
	case string(api.RefreshToken):
		panic("Not Implemented")
	default:
		http.Error(rw, "Unsupported grant_type", http.StatusBadRequest)

		return
	}
}

func UserInfo(
	rw http.ResponseWriter,
	req *http.Request,
) {
	bearer := req.Header.Get("Authorization")

	tokens := strings.Split(bearer, " ")

	if len(tokens) != 2 {
		http.Error(rw, "Invalid Authorization header", http.StatusUnauthorized)

		return
	}

	if tokens[0] != "Bearer" {
		http.Error(rw, "Invalid Authorization header", http.StatusUnauthorized)

		return
	}

	// FIXME: validate token

	res := api.UserInfoResponseSchema{
		Email: "",
		Sub:   "sub",
	}

	buf := bytes.Buffer{}

	if err := json.NewEncoder(&buf).Encode(res); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	rw.Write(buf.Bytes())
}

func Certs(
	rw http.ResponseWriter,
	req *http.Request,
) {
	db, err := sql.Open("d1", "DB")
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		slog.Error("error opening database")

		return
	}

	queries := schema.New(db)

	keys, err := queries.ListJwkSet(req.Context())
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		slog.Error(err.Error())

		slog.Error("error listing jwk set")

		return
	}

	jwksets := make([]api.JWKSet, len(keys))

	slog.Info(fmt.Sprintf("keys: %+v", keys))

	for i, key := range keys {
		pk, err := base64.StdEncoding.DecodeString(key.DerKeyBase64)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		parsed, err := x509.ParsePKCS1PrivateKey(pk)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		sign := token.SignKey{
			ID:  key.ID,
			Key: parsed,
		}

		jwksets[i] = api.JWKSet{
			Alg: sign.Cert().Alg,
			E:   sign.Cert().E,
			Kid: sign.Cert().KID,
			Kty: sign.Cert().KTY,
			N:   sign.Cert().N,
			Use: sign.Cert().Use,
		}
	}

	res := api.CertsResponseSchema{
		Keys: jwksets,
	}

	buf := bytes.Buffer{}

	if err := json.NewEncoder(&buf).Encode(res); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	rw.Write(buf.Bytes())
}
