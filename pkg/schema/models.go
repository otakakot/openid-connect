// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0

package schema

type Client struct {
	ID                 string
	HashedSecret       string
	DerPublicKeyBase64 string
	Name               string
	RedirectUri        string
}

type JwkSet struct {
	ID                  string
	DerPrivateKeyBase64 string
}

type User struct {
	ID             string
	Email          string
	HashedPassword string
}
