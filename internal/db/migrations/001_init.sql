-- +goose Up
CREATE TABLE services (
    id                      TEXT PRIMARY KEY,
    display_name            TEXT NOT NULL,
    tagline                 TEXT,
    domain                  TEXT NOT NULL UNIQUE,
    auth_host               TEXT UNIQUE,
    callback_url            TEXT NOT NULL,
    logo_html               TEXT,
    bg_image                TEXT,
    bg_css                  TEXT,
    theme                   TEXT NOT NULL DEFAULT 'light',
    accent_color            TEXT NOT NULL DEFAULT '#2563EB',
    email_from_name         TEXT NOT NULL,
    auto_register           INTEGER NOT NULL DEFAULT 0,
    default_role            TEXT,
    default_org             TEXT,
    require_role            TEXT,
    enforce_org             INTEGER NOT NULL DEFAULT 0,
    is_default              INTEGER NOT NULL DEFAULT 0,
    auth_google             INTEGER NOT NULL DEFAULT 1,
    auth_microsoft          INTEGER NOT NULL DEFAULT 0,
    auth_magic_link         INTEGER NOT NULL DEFAULT 1,
    auth_password           INTEGER NOT NULL DEFAULT 0,
    google_client_id        TEXT,
    google_client_secret    TEXT,
    microsoft_client_id     TEXT,
    microsoft_client_secret TEXT,
    jwt_cookie_name         TEXT NOT NULL DEFAULT 'auth_token',
    access_token_ttl        TEXT NOT NULL DEFAULT 'PT15M',
    refresh_token_max_age   TEXT,
    active                  INTEGER NOT NULL DEFAULT 1,
    updated_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE UNIQUE INDEX idx_services_default ON services(is_default) WHERE is_default = 1;

CREATE TABLE users (
    id              INTEGER PRIMARY KEY,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT,
    name            TEXT,
    roles           TEXT NOT NULL DEFAULT '',
    orgs            TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    last_login      TEXT,
    deactivated_at  TEXT
);

CREATE TABLE magic_tokens (
    id           INTEGER PRIMARY KEY,
    token        TEXT NOT NULL UNIQUE,
    email        TEXT NOT NULL,
    service_id   TEXT REFERENCES services(id) ON DELETE SET NULL,
    redirect_uri TEXT,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    expires_at   TEXT NOT NULL,
    used         INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_magic_tokens_email   ON magic_tokens(email);
CREATE INDEX idx_magic_tokens_expires ON magic_tokens(expires_at);

CREATE TABLE refresh_tokens (
    id                INTEGER PRIMARY KEY,
    token_hash        TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64),
    email             TEXT NOT NULL,
    service_id        TEXT REFERENCES services(id) ON DELETE SET NULL,
    family_id         TEXT NOT NULL,
    parent_id         INTEGER REFERENCES refresh_tokens(id),
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    expires_at        TEXT NOT NULL,
    family_expires_at TEXT,
    used              INTEGER NOT NULL DEFAULT 0,
    revoked           INTEGER NOT NULL DEFAULT 0,
    revoked_reason    TEXT,
    ip_address        TEXT,
    user_agent        TEXT
);

CREATE INDEX idx_refresh_tokens_family      ON refresh_tokens(family_id);
CREATE INDEX idx_refresh_tokens_expires     ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_fam_expires ON refresh_tokens(family_expires_at)
    WHERE family_expires_at IS NOT NULL;

CREATE TABLE audit_events (
    id           INTEGER PRIMARY KEY,
    event_type   TEXT NOT NULL,
    auth_method  TEXT,
    email        TEXT,
    service_id   TEXT,
    ip_address   TEXT,
    user_agent   TEXT,
    success      INTEGER NOT NULL,
    details      TEXT,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE INDEX idx_audit_events_created ON audit_events(created_at);
CREATE INDEX idx_audit_events_email   ON audit_events(email);
CREATE INDEX idx_audit_events_service ON audit_events(service_id, created_at);

-- +goose Down
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS magic_tokens;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS services;
