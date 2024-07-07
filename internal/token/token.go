package token

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AccessToken struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
}

func ParceAccessToken(
	str string,
	sign string,
) (*AccessToken, error) {
	token, err := jwt.Parse(str, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}

		return []byte(sign), nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		iss := claims["iss"].(string)
		sub := claims["sub"].(string)
		exp := int64(claims["exp"].(float64))
		iat := int64(claims["iat"].(float64))

		return &AccessToken{
			Iss: iss,
			Sub: sub,
			Exp: exp,
			Iat: iat,
		}, nil
	}

	return nil, fmt.Errorf("invalid token")
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

type SignKey struct {
	ID  string
	Key *rsa.PrivateKey
}

func GenerateSignKey() SignKey {
	reader := rand.Reader

	bitSize := 2048

	key, _ := rsa.GenerateKey(reader, bitSize)

	return SignKey{
		ID:  "id",
		Key: key,
	}
}

type Cert struct {
	KID string `json:"kid"`
	KTY string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (sk SignKey) Cert() Cert {
	data := make([]byte, 8)

	binary.BigEndian.PutUint64(data, uint64(sk.Key.PublicKey.E))

	i := 0
	for ; i < len(data); i++ {
		if data[i] != 0x0 {
			break
		}
	}

	e := base64.RawURLEncoding.EncodeToString(data[i:])

	return Cert{
		KID: sk.ID,
		KTY: "RSA",
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(sk.Key.PublicKey.N.Bytes()),
		E:   e,
	}
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
	sign SignKey,
) string {
	claims := jwt.MapClaims{
		"iss": it.Iss,
		"sub": it.Sub,
		"aud": it.Aud,
		"exp": it.Exp,
		"iat": it.Iat,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	token.Header["kid"] = sign.ID

	str, _ := token.SignedString(sign.Key)

	return str
}
