package handler

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/syumai/workers/cloudflare"
	_ "github.com/syumai/workers/cloudflare/d1"
	"golang.org/x/crypto/bcrypt"

	"github.com/otakakot/openid-connect/internal/core"
	"github.com/otakakot/openid-connect/internal/database"
	"github.com/otakakot/openid-connect/pkg/api"
	"github.com/otakakot/openid-connect/pkg/schema"
)

func OpenIDConfiguration(
	rw http.ResponseWriter,
	req *http.Request,
) {
	issuer := req.URL.Scheme + "://" + req.Host

	conf := api.OpenIDConfigurationResponseSchema{
		Issuer:                           issuer,
		AuthorizationEndpoint:            issuer + "/authorize",
		JwksUri:                          issuer + "/certs",
		RevocationEndpoint:               issuer + "/revoke",
		TokenEndpoint:                    issuer + "/token",
		UserinfoEndpoint:                 issuer + "/userinfo",
		SubjectTypesSupported:            []string{"public"},
		IdTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	if err := json.NewEncoder(rw).Encode(conf); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}
}

func Authorize(
	rw http.ResponseWriter,
	req *http.Request,
) {
	cid := req.URL.Query().Get("client_id")

	cli, err := schema.New(database.D1).FindClientByID(req.Context(), cid)
	if err != nil {
		slog.Warn("failed to find client. error: " + err.Error() + " client_id: " + cid)

		http.Error(rw, err.Error(), http.StatusBadRequest)

		return
	}

	red := req.URL.Query().Get("redirect_uri")

	if cli.RedirectUri != red {
		redirectBuf := bytes.Buffer{}

		redirectBuf.WriteString(cli.RedirectUri)

		values := url.Values{
			"error": {string(api.AuthorizeErrorTypeInvalidRequest)},
		}

		redirectBuf.WriteByte('?')

		redirectBuf.WriteString(values.Encode())

		redirect, _ := url.ParseRequestURI(redirectBuf.String())

		http.Redirect(rw, req, redirect.String(), http.StatusFound)

		return
	}

	sessionKV, err := cloudflare.NewKVNamespace(database.KVNSSession)
	if err != nil {
		redirectBuf := bytes.Buffer{}

		redirectBuf.WriteString(red)

		values := url.Values{
			"error": {string(api.AuthorizeErrorTypeServerError)},
		}

		redirectBuf.WriteByte('?')

		redirectBuf.WriteString(values.Encode())

		redirect, _ := url.ParseRequestURI(redirectBuf.String())

		http.Redirect(rw, req, redirect.String(), http.StatusFound)

		return
	}

	rt := req.URL.Query().Get("response_type")

	if rt != "code" {
		redirectBuf := bytes.Buffer{}

		redirectBuf.WriteString(red)

		values := url.Values{
			"error": {string(api.AuthorizeErrorTypeInvalidRequest)},
		}

		redirectBuf.WriteByte('?')

		redirectBuf.WriteString(values.Encode())

		redirect, _ := url.ParseRequestURI(redirectBuf.String())

		http.Redirect(rw, req, redirect.String(), http.StatusFound)

		return
	}

	sc := req.URL.Query().Get("scope")

	// slog.Info(sc)

	// TODO: validate scope

	st := req.URL.Query().Get("state")
	if st == "" {
		st = rand.Text()
	}

	session := core.State{
		ResponseType: rt,
		ClientID:     cid,
		RedirectURI:  red,
		Scope:        sc,
		State:        st,
	}

	sessionBuf := bytes.Buffer{}

	if err := json.NewEncoder(&sessionBuf).Encode(session); err != nil {
		redirectBuf := bytes.Buffer{}

		redirectBuf.WriteString(red)

		values := url.Values{
			"error": {string(api.AuthorizeErrorTypeServerError)},
		}

		redirectBuf.WriteByte('?')

		redirectBuf.WriteString(values.Encode())

		redirect, _ := url.ParseRequestURI(redirectBuf.String())

		http.Redirect(rw, req, redirect.String(), http.StatusFound)

		return
	}

	id := rand.Text()

	if err := sessionKV.PutString(id, base64.StdEncoding.EncodeToString(sessionBuf.Bytes()), nil); err != nil {
		redirectBuf := bytes.Buffer{}

		redirectBuf.WriteString(red)

		values := url.Values{
			"error": {string(api.AuthorizeErrorTypeServerError)},
		}

		redirectBuf.WriteByte('?')

		redirectBuf.WriteString(values.Encode())

		redirect, _ := url.ParseRequestURI(redirectBuf.String())

		http.Redirect(rw, req, redirect.String(), http.StatusFound)

		return
	}

	http.SetCookie(rw, &http.Cookie{
		Name:     core.CookeyState,
		Value:    id,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	redirectBuf := bytes.Buffer{}

	redirectBuf.WriteString("/login")

	redirect, _ := url.ParseRequestURI(redirectBuf.String())

	http.Redirect(rw, req, redirect.String(), http.StatusFound)
}

func Login(
	rw http.ResponseWriter,
	req *http.Request,
) {
	switch req.Method {
	case http.MethodGet:
		session, err := req.Cookie(core.CookeySession)
		if err != nil {
			rw.Write([]byte(view))

			return
		}

		sid, err := req.Cookie(core.CookeyState)
		if err != nil {
			slog.Warn("failed to get session cookie. error: " + err.Error())

			// TODO: redirect
			http.Error(rw, err.Error(), http.StatusUnauthorized)

			return
		}

		user, err := schema.New(database.D1).FindUserByID(req.Context(), session.Value)
		if err != nil {
			slog.Warn("failed to find user. error: " + err.Error() + " email: " + req.FormValue("email"))

			http.Error(rw, err.Error(), http.StatusUnauthorized)

			return
		}

		userBuf := bytes.Buffer{}

		if err := json.NewEncoder(&userBuf).Encode(user); err != nil {
			slog.Error("failed to encode user. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		userKV, err := cloudflare.NewKVNamespace(database.KVNSUser)
		if err != nil {
			slog.Error("failed to create user KV namespace. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		if err := userKV.PutString(sid.Value, base64.StdEncoding.EncodeToString(userBuf.Bytes()), nil); err != nil {
			slog.Error("failed to put user. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		http.Redirect(rw, req, "/callback", http.StatusFound)

		return
	case http.MethodPost:
		userKV, err := cloudflare.NewKVNamespace(database.KVNSUser)
		if err != nil {
			slog.Error("failed to create user KV namespace. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		sid, err := req.Cookie(core.CookeyState)
		if err != nil {
			slog.Warn("failed to get session cookie. error: " + err.Error())

			// TODO: redirect
			http.Error(rw, err.Error(), http.StatusUnauthorized)

			return
		}

		user, err := schema.New(database.D1).FindUserByEmail(req.Context(), req.FormValue("email"))
		if err != nil {
			slog.Warn("failed to find user. error: " + err.Error() + " email: " + req.FormValue("email"))

			http.Error(rw, err.Error(), http.StatusUnauthorized)

			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(req.FormValue("password"))); err != nil {
			slog.Warn("invalid password. email: " + req.FormValue("email"))

			http.Error(rw, "invalid user", http.StatusUnauthorized)

			return
		}

		http.SetCookie(rw, &http.Cookie{
			Name:     core.CookeySession,
			Value:    user.ID,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteDefaultMode,
			MaxAge:   60 * 60 * 24 * 180,
		})

		userBuf := bytes.Buffer{}

		if err := json.NewEncoder(&userBuf).Encode(user); err != nil {
			slog.Error("failed to encode user. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		if err := userKV.PutString(sid.Value, base64.StdEncoding.EncodeToString(userBuf.Bytes()), nil); err != nil {
			slog.Error("failed to put user. error: " + err.Error())

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
	sessionKV, err := cloudflare.NewKVNamespace(database.KVNSSession)
	if err != nil {
		slog.Error("failed to create session KV namespace. error: " + err.Error())

		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	userKV, err := cloudflare.NewKVNamespace(database.KVNSUser)
	if err != nil {
		slog.Error("failed to create user KV namespace. error: " + err.Error())

		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	codeKV, err := cloudflare.NewKVNamespace(database.KVNSCode)
	if err != nil {
		slog.Error("failed to create code KV namespace. error: " + err.Error())

		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	sid, err := req.Cookie(core.CookeyState)
	if err != nil {
		slog.Warn("failed to get session cookie. error: " + err.Error())

		http.Error(rw, err.Error(), http.StatusUnauthorized)

		return
	}

	sessionStr, err := sessionKV.GetString(sid.Value, nil)
	if err != nil {
		slog.Warn("failed to find session. error: " + err.Error())

		http.Error(rw, err.Error(), http.StatusUnauthorized)

		return
	}

	sessionBt, _ := base64.StdEncoding.DecodeString(sessionStr)

	session := core.State{}

	if err := json.NewDecoder(bytes.NewReader(sessionBt)).Decode(&session); err != nil {
		slog.Error("failed to decode session. error: " + err.Error())

		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	if err := sessionKV.Delete(sid.Value); err != nil {
		slog.Error("error deleting session")
	}

	userStr, err := userKV.GetString(sid.Value, nil)
	if err != nil {
		redirectBuf := bytes.Buffer{}

		redirectBuf.WriteString(session.RedirectURI)

		values := url.Values{
			"error": {string(api.AuthorizeErrorTypeAccessDenied)},
		}

		redirectBuf.WriteByte('?')

		redirectBuf.WriteString(values.Encode())

		redirect, _ := url.ParseRequestURI(redirectBuf.String())

		http.Redirect(rw, req, redirect.String(), http.StatusFound)

		return
	}

	if err := userKV.Delete(sid.Value); err != nil {
		slog.Error("failed to delete user. error: " + err.Error())
	}

	code := rand.Text()

	if err := codeKV.PutString(code, userStr, nil); err != nil {
		redirectBuf := bytes.Buffer{}

		redirectBuf.WriteString(session.RedirectURI)

		values := url.Values{
			"error": {string(api.AuthorizeErrorTypeServerError)},
		}

		redirectBuf.WriteByte('?')

		redirectBuf.WriteString(values.Encode())

		redirect, _ := url.ParseRequestURI(redirectBuf.String())

		http.Redirect(rw, req, redirect.String(), http.StatusFound)

		return
	}

	cookie := http.Cookie{
		Name:   core.CookeyState,
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
		codeKV, err := cloudflare.NewKVNamespace(database.KVNSCode)
		if err != nil {
			slog.Error("failed to create code KV namespace. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		code := req.FormValue("code")

		userStr, err := codeKV.GetString(code, nil)
		if err != nil {
			slog.Warn("failed to find code. error: " + err.Error())

			res := api.TokenErrorSchema{
				Error: api.TokenErrorTypeInvalidRequest,
			}

			if err := json.NewEncoder(rw).Encode(res); err != nil {
				slog.Error("failed to encode token error. error: " + err.Error())

				http.Error(rw, err.Error(), http.StatusInternalServerError)

				return
			}

			rw.WriteHeader(http.StatusBadRequest)

			return
		}

		if err := codeKV.Delete(code); err != nil {
			slog.Error("failed to delete code. error: " + err.Error())
		}

		userBt, _ := base64.StdEncoding.DecodeString(userStr)

		user := core.User{}

		if err := json.NewDecoder(bytes.NewReader(userBt)).Decode(&user); err != nil {
			slog.Error("failed to decode user. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		cid := req.FormValue("client_id")

		cli, err := schema.New(database.D1).FindClientByID(req.Context(), cid)
		if err != nil {
			slog.Warn("failed to find client. error: " + err.Error())

			res := api.TokenErrorSchema{
				Error: api.TokenErrorTypeInvalidClient,
			}

			if err := json.NewEncoder(rw).Encode(res); err != nil {
				slog.Error("failed to encode token error. error: " + err.Error())

				http.Error(rw, err.Error(), http.StatusInternalServerError)

				return
			}

			rw.WriteHeader(http.StatusBadRequest)

			return
		}

		if req.FormValue("client_secret") == "" && req.FormValue("client_assertion") == "" {
			slog.WarnContext(req.Context(), "client_secret or client_assertion is required")

			res := api.TokenErrorSchema{
				Error: api.TokenErrorTypeInvalidClient,
			}

			if err := json.NewEncoder(rw).Encode(res); err != nil {
				slog.Error("failed to encode token error. error: " + err.Error())

				http.Error(rw, err.Error(), http.StatusInternalServerError)

				return
			}

			rw.WriteHeader(http.StatusBadRequest)
		}

		if req.FormValue("client_secret") != "" && req.FormValue("client_assertion") != "" {
			slog.WarnContext(req.Context(), "client_secret and client_assertion are both provided")

			res := api.TokenErrorSchema{
				Error: api.TokenErrorTypeInvalidClient,
			}

			if err := json.NewEncoder(rw).Encode(res); err != nil {
				slog.Error("failed to encode token error. error: " + err.Error())

				http.Error(rw, err.Error(), http.StatusInternalServerError)

				return
			}

			rw.WriteHeader(http.StatusBadRequest)
		}

		if csec := req.FormValue("client_secret"); csec != "" {
			if err := bcrypt.CompareHashAndPassword([]byte(cli.HashedSecret), []byte(csec)); err != nil {
				slog.Warn("invalid client_secret")

				res := api.TokenErrorSchema{
					Error: api.TokenErrorTypeInvalidClient,
				}

				if err := json.NewEncoder(rw).Encode(res); err != nil {
					slog.Error("failed to encode token error. error: " + err.Error())

					http.Error(rw, err.Error(), http.StatusInternalServerError)

					return
				}

				rw.WriteHeader(http.StatusBadRequest)

				return
			}
		}

		// TODO: client_assertion_type の検証

		if cas := req.FormValue("client_assertion"); cas != "" {
			slog.InfoContext(req.Context(), "client_assertion: "+cas)

			slog.InfoContext(req.Context(), "client public key: "+cli.DerPublicKeyBase64)

			pubkey, err := core.DecodeDERPublicKeyBase64(cli.DerPublicKeyBase64)
			if err != nil {
				slog.Error("failed to decode der public key base64. error: " + err.Error())

				http.Error(rw, err.Error(), http.StatusInternalServerError)

				return
			}

			claims, err := core.ValidateClientAssertion(cas, pubkey)
			if err != nil {
				slog.Warn("failed to validate token. error: " + err.Error())

				res := api.TokenErrorSchema{
					Error: api.TokenErrorTypeInvalidClient,
				}

				if err := json.NewEncoder(rw).Encode(res); err != nil {
					slog.Error("failed to encode token error. error: " + err.Error())

					http.Error(rw, err.Error(), http.StatusInternalServerError)

					return
				}

				rw.WriteHeader(http.StatusBadRequest)

				return
			}

			slog.InfoContext(req.Context(), fmt.Sprintf("%+v", claims))

			// TODO: claims の検証
		}

		red := req.FormValue("redirect_uri")

		if cli.RedirectUri != red {
			slog.Warn("invalid redirect_uri. redirect_uri: " + red)

			res := api.TokenErrorSchema{
				Error: api.TokenErrorTypeInvalidRequest,
			}

			if err := json.NewEncoder(rw).Encode(res); err != nil {
				slog.Error("failed to encode token error. error: " + err.Error())

				http.Error(rw, err.Error(), http.StatusInternalServerError)

				return
			}

			rw.WriteHeader(http.StatusBadRequest)

			return
		}

		// scope := req.FormValue("scope")

		// slog.Info(scope)

		iss := req.URL.Scheme + "://" + req.Host

		at := core.GenerateAccessToken(iss, user.ID)

		it := core.GenerateIDToken(iss, user.ID, cid, "")

		rt := rand.Text()

		rtKV, err := cloudflare.NewKVNamespace(database.KVNSRefreshToken)
		if err != nil {
			slog.Error("failed to create refresh token KV namespace. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		if err := rtKV.PutString(rt, userStr, nil); err != nil {
			slog.Error("failed to put refresh token. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		keys, err := schema.New(database.D1).ListJwkSet(req.Context())
		if err != nil {
			slog.Warn("failed to find jwk set. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		pk, err := base64.StdEncoding.DecodeString(keys[0].DerPrivateKeyBase64)
		if err != nil {
			slog.Error("failed to decode der private key base64. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		parsed, err := x509.ParsePKCS1PrivateKey(pk)
		if err != nil {
			slog.Error("failed to parse pkcs1 private key. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		sign := core.SignKey{
			ID:  keys[0].ID,
			Key: parsed,
		}

		res := api.TokenResponseSchema{
			AccessToken:  at.JWT("secret"),
			ExpiresIn:    3600,
			IdToken:      it.JWT(sign),
			RefreshToken: rt,
			TokenType:    "Bearer",
		}

		if err := json.NewEncoder(rw).Encode(res); err != nil {
			slog.Error("failed to encode token response. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		return
	case string(api.TokenRequestSchemaGrantTypeRefreshToken):
		ort := req.FormValue("refresh_token")

		rtKV, err := cloudflare.NewKVNamespace(database.KVNSRefreshToken)
		if err != nil {
			slog.Error("failed to create refresh token KV namespace. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		userStr, err := rtKV.GetString(ort, nil)
		if err != nil {
			slog.Warn("failed to find refresh token. error: " + err.Error())

			res := api.TokenErrorSchema{
				Error: api.TokenErrorTypeInvalidRequest,
			}

			if err := json.NewEncoder(rw).Encode(res); err != nil {
				slog.Error("failed to encode token error. error: " + err.Error())

				http.Error(rw, err.Error(), http.StatusInternalServerError)

				return
			}

			rw.WriteHeader(http.StatusBadRequest)

			return
		}

		userBt, _ := base64.StdEncoding.DecodeString(userStr)

		user := core.User{}

		if err := json.NewDecoder(bytes.NewReader(userBt)).Decode(&user); err != nil {
			slog.Error("failed to decode user. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		iss := req.URL.Scheme + "://" + req.Host

		at := core.GenerateAccessToken(iss, user.ID)

		nrt := rand.Text()

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

		if err := json.NewEncoder(rw).Encode(res); err != nil {
			slog.Error("failed to encode token response. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		return
	default:
		slog.Warn("unsupported grant_type: " + req.FormValue("grant_type"))

		res := api.TokenErrorSchema{
			Error: api.TokenErrorTypeUnsupportedGrantType,
		}

		if err := json.NewEncoder(rw).Encode(res); err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		rw.WriteHeader(http.StatusBadRequest)

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
		slog.Warn("invalid Authorization header. header: " + bearer)

		http.Error(rw, "Invalid Authorization header", http.StatusUnauthorized)

		return
	}

	if tokens[0] != "Bearer" {
		slog.Warn("invalid Authorization header. header: " + bearer)

		http.Error(rw, "Invalid Authorization header", http.StatusUnauthorized)

		return
	}

	at, err := core.ParceAccessToken(tokens[1], "secret")
	if err != nil {
		slog.Warn("failed to parse access token. error: " + err.Error())

		http.Error(rw, err.Error(), http.StatusUnauthorized)

		return
	}

	user, err := schema.New(database.D1).FindUserByID(req.Context(), at.Sub)
	if err != nil {
		slog.Warn("failed to find user. error: " + err.Error() + " sub: " + at.Sub)

		http.Error(rw, err.Error(), http.StatusUnauthorized)

		return
	}

	res := api.UserInfoResponseSchema{
		Sub:   user.ID,
		Email: user.Email,
	}

	if err := json.NewEncoder(rw).Encode(res); err != nil {
		slog.Error("failed to encode user info response. error: " + err.Error())

		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}
}

func Certs(
	rw http.ResponseWriter,
	req *http.Request,
) {
	keys, err := schema.New(database.D1).ListJwkSet(req.Context())
	if err != nil {
		slog.Error("failed to list jwk set. error: " + err.Error())

		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}

	jwksets := make([]api.JWKSet, len(keys))

	for i, key := range keys {
		pk, err := base64.StdEncoding.DecodeString(key.DerPrivateKeyBase64)
		if err != nil {
			slog.Error("failed to decode der private key base64. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		parsed, err := x509.ParsePKCS1PrivateKey(pk)
		if err != nil {
			slog.Error("failed to parse pkcs1 private key. error: " + err.Error())

			http.Error(rw, err.Error(), http.StatusInternalServerError)

			return
		}

		sign := core.SignKey{
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

	if err := json.NewEncoder(rw).Encode(res); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}
}

func Revoke(
	rw http.ResponseWriter,
	req *http.Request,
) {
	rtKV, err := cloudflare.NewKVNamespace(database.KVNSRefreshToken)
	if err != nil {
		slog.Error("failed to create refresh token KV namespace. error: " + err.Error())

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
		slog.Error("failed to delete refresh token. error: " + err.Error())

		http.Error(rw, err.Error(), http.StatusInternalServerError)

		return
	}
}
