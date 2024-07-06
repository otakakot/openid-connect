-- name: ListJwkSet :many
SELECT
    *
FROM
    jwk_sets;

-- name: FindJwkSetByID :one
SELECT
    *
FROM
    jwk_sets
WHERE
    id = ?;

-- name: FindClientByID :one
SELECT
    *
FROM
    clients
WHERE
    id = ?;
