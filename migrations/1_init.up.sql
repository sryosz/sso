CREATE TABLE IF NOT EXISTS users
(
    id        serial PRIMARY KEY,
    email     TEXT  NOT NULL UNIQUE,
    pass_hash bytea NOT NULL

);
CREATE INDEX IF NOT EXISTS idx_email ON users (email);

CREATE TABLE IF NOT EXISTS apps
(
    id     INTEGER PRIMARY KEY,
    name   TEXT NOT NULL UNIQUE,
    secret TEXT NOT NULL UNIQUE
)