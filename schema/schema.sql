CREATE TABLE IF NOT EXISTS clients (
    id TEXT PRIMARY KEY,
    secret_base64 TEXT NOT NULL,
    name VARCHAR(255) NOT NULL,
    redirect_uri TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jwk_sets (
    id TEXT PRIMARY KEY,
    der_key_base64 TEXT NOT NULL
);
