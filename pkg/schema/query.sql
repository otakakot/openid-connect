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

-- name: FindUserByID :one
SELECT
    *
FROM
    users
WHERE
    id = ?;

-- name: FindUserByEmail :one
SELECT
    *
FROM
    users
WHERE
    email = ?;
