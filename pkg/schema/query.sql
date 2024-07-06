-- name: ListJwkSet :many
SELECT
    *
FROM
    jwk_sets;

-- name: FindClientByID :one
SELECT
    *
FROM
    clients
WHERE
    id = ?;
