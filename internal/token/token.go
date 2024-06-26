package token

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AccessToken struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
}

func GenerateAccessToken(
	iss string,
	sub string,
) AccessToken {
	now := time.Now()

	return AccessToken{
		Iss: iss,
		Sub: sub,
		Exp: now.Add(time.Hour).Unix(),
		Iat: now.Unix(),
	}
}

func (at AccessToken) JWT(
	sign string,
) string {
	claims := jwt.MapClaims{
		"iss": at.Iss,
		"sub": at.Sub,
		"exp": at.Exp,
		"iat": at.Iat,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	str, _ := token.SignedString([]byte(sign))

	return str
}

type IDToken struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
}

func GenerateIDToken(
	iss string,
	sub string,
	aud string,
	jti string,
) IDToken {
	now := time.Now()

	return IDToken{
		Iss: iss,
		Sub: sub,
		Aud: aud,
		Exp: now.Add(time.Hour).Unix(),
		Iat: now.Unix(),
	}
}

func (it IDToken) JWT(
	sign string,
) string {
	claims := jwt.MapClaims{
		"iss": it.Iss,
		"sub": it.Sub,
		"aud": it.Aud,
		"exp": it.Exp,
		"iat": it.Iat,
	}

	// TODO: RS256
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	str, _ := token.SignedString([]byte(""))

	return str
}
