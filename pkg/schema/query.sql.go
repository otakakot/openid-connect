// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0
// source: query.sql

package schema

import (
	"context"
)

const findClientByID = `-- name: FindClientByID :one
SELECT
    id, hashed_secret, name, redirect_uri
FROM
    clients
WHERE
    id = ?
`

func (q *Queries) FindClientByID(ctx context.Context, id string) (Client, error) {
	row := q.db.QueryRowContext(ctx, findClientByID, id)
	var i Client
	err := row.Scan(
		&i.ID,
		&i.HashedSecret,
		&i.Name,
		&i.RedirectUri,
	)
	return i, err
}

const findJwkSetByID = `-- name: FindJwkSetByID :one
SELECT
    id, der_key_base64
FROM
    jwk_sets
WHERE
    id = ?
`

func (q *Queries) FindJwkSetByID(ctx context.Context, id string) (JwkSet, error) {
	row := q.db.QueryRowContext(ctx, findJwkSetByID, id)
	var i JwkSet
	err := row.Scan(&i.ID, &i.DerKeyBase64)
	return i, err
}

const listJwkSet = `-- name: ListJwkSet :many
SELECT
    id, der_key_base64
FROM
    jwk_sets
`

func (q *Queries) ListJwkSet(ctx context.Context) ([]JwkSet, error) {
	rows, err := q.db.QueryContext(ctx, listJwkSet)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []JwkSet
	for rows.Next() {
		var i JwkSet
		if err := rows.Scan(&i.ID, &i.DerKeyBase64); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}
