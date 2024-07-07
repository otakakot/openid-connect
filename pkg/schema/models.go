// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0

package schema

type Client struct {
	ID           string
	HashedSecret string
	Name         string
	RedirectUri  string
}

type JwkSet struct {
	ID           string
	DerKeyBase64 string
}

type User struct {
	ID             string
	Email          string
	HashedPassword string
}
