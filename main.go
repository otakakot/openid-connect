package main

import (
	"bytes"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"strings"

	"github.com/syumai/workers"
	"github.com/syumai/workers/cloudflare"
	_ "github.com/syumai/workers/cloudflare/d1"
	"golang.org/x/crypto/bcrypt"

	"github.com/otakakot/openid-connect/internal/token"
	"github.com/otakakot/openid-connect/pkg/api"
	"github.com/otakakot/openid-connect/pkg/schema"
)

func main() {
	http.HandleFunc("/.well-known/openid-configuration", OpenIDConfiguration) // OIDC

	http.HandleFunc("/authorize", Authorize) // OIDC

	http.HandleFunc("/login", Login) // IdP

	http.HandleFunc("/callback", Callback) // IdP

	http.HandleFunc("/token", Token) // OIDC

	http.HandleFunc("/userinfo", UserInfo) // OIDC

	http.HandleFunc("/certs", Certs) // OIDC

	http.HandleFunc("/revoke", Revoke) // OIDC

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
	codeKVNS         = "openid-connect-code"
	userKVNS         = "openid-connect-user"
	sessionKVNS      = "openid-connect-session"
	refreshTokenKVNS = "openid-connect-refresh-token"
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

	if rt != "code" {
		// TODO: redirect
		http.Error(rw, "Unsupported response_type", http.StatusBadRequest)

		return
	}

	cid := req.URL.Query().Get("client_id")

	db, err := sql.Open("d1", "DB")
	if err != nil {
		// TODO: redirect
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		slog.Error("error opening database")

		return
	}

	queries := schema.New(db)

	cli, err := queries.FindClientByID(req.Context(), cid)
	if err != nil {
		// TODO: redirect
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		slog.Error("error finding client")

		return
	}

	red := req.URL.Query().Get("redirect_uri")

	if cli.RedirectUri != red {
		// TODO: redirect
		http.Error(rw, "Invalid redirect_uri", http.StatusBadRequest)

		return
	}

	sc := req.URL.Query().Get("scope")

	// slog.Info(sc)

	// TODO: validate scope

	st := req.URL.Query().Get("state")

	session := Session{
		ResponseType: rt,
		ClientID:     cid,
		RedirectURI:  red,
		Scope:        sc,
		State:        st,
	}

	sessionBuf := bytes.Buffer{}

	if err := json.NewEncoder(&sessionBuf).Encode(session); err != nil {
		// TODO: redirect
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	id := GenerateID(10)

	if err := sessionKV.PutString(id, base64.StdEncoding.EncodeToString(sessionBuf.Bytes()), nil); err != nil {
		// TODO: redirect
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
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
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

		db, err := sql.Open("d1", "DB")
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)

			slog.Error("error opening database")

			return
		}

		queries := schema.New(db)

		user, err := queries.FindUserByEmail(req.Context(), req.FormValue("email"))
		if err != nil {
			http.Error(rw, err.Error(), http.StatusUnauthorized)

			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(req.FormValue("password"))); err != nil {
			http.Error(rw, "invalid user", http.StatusUnauthorized)

			return
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
	slog.Info("grant_type: " + req.FormValue("grant_type"))

	switch req.FormValue("grant_type") {
	case string(api.TokenRequestSchemaGrantTypeAuthorizationCode):
		db, err := sql.Open("d1", "DB")
		if err != nil {
			slog.Error("error opening database")

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		queries := schema.New(db)

		codeKV, err := cloudflare.NewKVNamespace(codeKVNS)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		code := req.FormValue("code")

		userStr, err := codeKV.GetString(code, nil)
		if err != nil {
			slog.Warn("failed to find code. error: " + err.Error())

			res := api.TokenErrorSchema{
				Error: api.InvalidRequest,
			}

			buf := bytes.Buffer{}

			if err := json.NewEncoder(&buf).Encode(res); err != nil {
				http.Error(rw, err.Error(), http.StatusInternalServerError)

				return
			}

			rw.Write(buf.Bytes())

			rw.WriteHeader(http.StatusBadRequest)

			return
		}

		if err := codeKV.Delete(code); err != nil {
			slog.Error("error deleting code. error: " + err.Error())
		}

		userBt, _ := base64.StdEncoding.DecodeString(userStr)

		user := User{}

		if err := json.NewDecoder(bytes.NewReader(userBt)).Decode(&user); err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		cid := req.FormValue("client_id")

		cli, err := queries.FindClientByID(req.Context(), cid)
		if err != nil {
			slog.Error("failed to find client. error: " + err.Error())

			res := api.TokenErrorSchema{
				Error: api.InvalidClient,
			}

			buf := bytes.Buffer{}

			if err := json.NewEncoder(&buf).Encode(res); err != nil {
				http.Error(rw, err.Error(), http.StatusInternalServerError)

				return
			}

			rw.Write(buf.Bytes())

			rw.WriteHeader(http.StatusBadRequest)

			return
		}

		csec := req.FormValue("client_secret")

		if err := bcrypt.CompareHashAndPassword([]byte(cli.HashedSecret), []byte(csec)); err != nil {
			slog.Warn("invalid client_secret")

			res := api.TokenErrorSchema{
				Error: api.InvalidClient,
			}

			buf := bytes.Buffer{}

			if err := json.NewEncoder(&buf).Encode(res); err != nil {
				http.Error(rw, err.Error(), http.StatusInternalServerError)

				return
			}

			rw.Write(buf.Bytes())

			rw.WriteHeader(http.StatusBadRequest)

			return
		}

		red := req.FormValue("redirect_uri")

		if cli.RedirectUri != red {
			slog.Warn("invalid redirect_uri. redirect_uri: " + red)

			res := api.TokenErrorSchema{
				Error: api.InvalidRequest,
			}

			buf := bytes.Buffer{}

			if err := json.NewEncoder(&buf).Encode(res); err != nil {
				http.Error(rw, err.Error(), http.StatusInternalServerError)

				return
			}

			rw.Write(buf.Bytes())

			rw.WriteHeader(http.StatusBadRequest)

			return
		}

		// scope := req.FormValue("scope")

		// slog.Info(scope)

		iss := req.URL.Scheme + "://" + req.Host

		at := token.GenerateAccessToken(iss, user.ID)

		it := token.GenerateIDToken(iss, user.ID, cid, "")

		rt := GenerateID(20)

		rtKV, err := cloudflare.NewKVNamespace(refreshTokenKVNS)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		if err := rtKV.PutString(rt, userStr, nil); err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		key, err := queries.FindJwkSetByID(req.Context(), "1234567890")
		if err != nil {
			slog.Error("failed to find jwk set. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		pk, err := base64.StdEncoding.DecodeString(key.DerKeyBase64)
		if err != nil {
			slog.Error("failed to decode der key base64. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		parsed, err := x509.ParsePKCS1PrivateKey(pk)
		if err != nil {
			slog.Error("failed to parse pkcs1 private key. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		sign := token.SignKey{
			ID:  key.ID,
			Key: parsed,
		}

		res := api.TokenResponseSchema{
			AccessToken:  at.JWT("secret"),
			ExpiresIn:    3600,
			IdToken:      it.JWT(sign),
			RefreshToken: rt,
			TokenType:    "Bearer",
		}

		buf := bytes.Buffer{}

		if err := json.NewEncoder(&buf).Encode(res); err != nil {
			slog.Error("failed to encode token response. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		rw.Write(buf.Bytes())

		return
	case string(api.TokenRequestSchemaGrantTypeRefreshToken):
		ort := req.FormValue("refresh_token")

		rtKV, err := cloudflare.NewKVNamespace(refreshTokenKVNS)
		if err != nil {
			slog.Error("failed to create refresh token KV namespace. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		userStr, err := rtKV.GetString(ort, nil)
		if err != nil {
			slog.Warn("failed to find refresh token. error: " + err.Error())

			res := api.TokenErrorSchema{
				Error: api.InvalidRequest,
			}

			buf := bytes.Buffer{}

			if err := json.NewEncoder(&buf).Encode(res); err != nil {
				http.Error(rw, err.Error(), http.StatusInternalServerError)

				return
			}

			rw.Write(buf.Bytes())

			rw.WriteHeader(http.StatusBadRequest)

			return
		}

		userBt, _ := base64.StdEncoding.DecodeString(userStr)

		user := User{}

		if err := json.NewDecoder(bytes.NewReader(userBt)).Decode(&user); err != nil {
			slog.Error("failed to decode user. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		iss := req.URL.Scheme + "://" + req.Host

		at := token.GenerateAccessToken(iss, user.ID)

		nrt := GenerateID(20)

		if err := rtKV.PutString(nrt, userStr, nil); err != nil {
			slog.Error("failed to put new refresh token. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		if err := rtKV.Delete(ort); err != nil {
			slog.Warn("failed to delete refresh token. error: " + err.Error())
		}

		res := api.TokenResponseSchema{
			AccessToken:  at.JWT("secret"),
			ExpiresIn:    3600,
			IdToken:      "",
			RefreshToken: nrt,
			TokenType:    "Bearer",
		}

		buf := bytes.Buffer{}

		if err := json.NewEncoder(&buf).Encode(res); err != nil {
			slog.Error("failed to encode token response. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		rw.Write(buf.Bytes())

		return
	default:
		slog.Warn("unsupported grant_type: " + req.FormValue("grant_type"))

		res := api.TokenErrorSchema{
			Error: api.UnsupportedGrantType,
		}

		buf := bytes.Buffer{}

		if err := json.NewEncoder(&buf).Encode(res); err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		rw.Write(buf.Bytes())

		rw.WriteHeader(http.StatusBadRequest)

		return
	}
}

func UserInfo(
	rw http.ResponseWriter,
	req *http.Request,
) {
	if req.Method != http.MethodGet && req.Method != http.MethodPost {
		http.Error(rw, "Method Not Allowed", http.StatusMethodNotAllowed)

		return
	}

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

	at, err := token.ParceAccessToken(tokens[1], "secret")
	if err != nil {
		http.Error(rw, err.Error(), http.StatusUnauthorized)

		return
	}

	db, err := sql.Open("d1", "DB")
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		slog.Error("error opening database")

		return
	}

	queries := schema.New(db)

	user, err := queries.FindUserByID(req.Context(), at.Sub)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusUnauthorized)

		return
	}

	res := api.UserInfoResponseSchema{
		Sub:   user.ID,
		Email: user.Email,
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
	if req.Method != http.MethodGet {
		http.Error(rw, "Method Not Allowed", http.StatusMethodNotAllowed)

		return
	}

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

func Revoke(
	rw http.ResponseWriter,
	req *http.Request,
) {
	if req.Method != http.MethodPost {
		http.Error(rw, "Method Not Allowed", http.StatusMethodNotAllowed)

		return
	}

	rtKV, err := cloudflare.NewKVNamespace(refreshTokenKVNS)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	rt := req.FormValue("token")

	if rt == "" {
		slog.Info("empty token")

		return
	}

	hint := req.FormValue("token_type_hint")

	// TODO: revoke access token
	if hint == string(api.RevokeFormdataBodyTokenTypeHintAccessToken) {
		http.Error(rw, "Not Implemented", http.StatusNotImplemented)

		return
	}

	slog.Info("deleted refresh token: " + rt)

	if err := rtKV.Delete(rt); err != nil {
		slog.Error(err.Error())

		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	rw.Write([]byte("OK"))
}
