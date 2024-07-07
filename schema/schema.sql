CREATE TABLE IF NOT EXISTS clients (
    id TEXT PRIMARY KEY,
    hashed_secret TEXT NOT NULL,
    name TEXT NOT NULL,
    redirect_uri TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jwk_sets (
    id TEXT PRIMARY KEY,
    der_key_base64 TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    hashed_password TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
