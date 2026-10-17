-- +goose Up
-- GitHub-innlogging (019): ny innloggingsmetode per tjeneste, og user_identities
-- får 'github' som fjerde provider-verdi.

-- Additivt for services: eksisterende tjenester får auth_github=0 og ingen
-- GitHub-konfig, så login-sidene er uendret ved utrulling.
-- Hemmeligheten lagres aldri her, bare navnet på miljøvariabelen. Samme
-- prefiksforsvar som i 014: en rad satt inn for hånd med sqlite3 skal ikke
-- kunne peke på KAUTH_PRIVATE_KEY_PEM, KAUTH_IDP_* eller andre interne hemmeligheter.
ALTER TABLE services ADD COLUMN auth_github INTEGER NOT NULL DEFAULT 0
    CHECK (auth_github IN (0,1));
ALTER TABLE services ADD COLUMN github_client_id TEXT;
ALTER TABLE services ADD COLUMN github_client_secret_env TEXT
    CHECK (github_client_secret_env IS NULL OR
           (github_client_secret_env GLOB 'KAUTH_SVC_[A-Z0-9_]*'
            AND github_client_secret_env NOT GLOB '*[^A-Z0-9_]*'));

-- SQLite kan ikke endre en CHECK, så user_identities bygges om (samme mønster
-- som 012). Ingen tabell refererer til user_identities, så DROP har ingen
-- CASCADE-effekt hos andre.
CREATE TABLE user_identities_new (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider     TEXT NOT NULL CHECK (provider IN ('google','microsoft','oidc','github')),
    issuer       TEXT NOT NULL,
    subject      TEXT NOT NULL,
    email        TEXT,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    last_used_at TEXT,
    admin_ok     INTEGER NOT NULL DEFAULT 0 CHECK (admin_ok IN (0,1)),
    UNIQUE (issuer, subject),
    -- En generisk eller GitHub-identitet skal aldri gi admin-innlogging.
    CHECK (provider NOT IN ('oidc','github') OR admin_ok = 0)
);

INSERT INTO user_identities_new (id, user_id, provider, issuer, subject, email, created_at, last_used_at, admin_ok)
SELECT id, user_id, provider, issuer, subject, email, created_at, last_used_at, admin_ok
FROM user_identities ORDER BY id;

-- Vakt: ombyggingen skal ikke miste eller duplisere en eneste identitet.
-- CHECK-bruddet ruller tilbake hele goose-transaksjonen.
CREATE TEMP TABLE _guard_015 (n INTEGER CHECK (n = 0));
INSERT INTO _guard_015
SELECT (SELECT count(*) FROM user_identities) - (SELECT count(*) FROM user_identities_new);
DROP TABLE _guard_015;

DROP TABLE user_identities;
ALTER TABLE user_identities_new RENAME TO user_identities;
CREATE INDEX idx_user_identities_user ON user_identities(user_id);

-- +goose Down
-- Feiler med vilje på CHECK hvis det finnes provider='github'-rader: de kan
-- ikke representeres i 012-skjemaet, og å slette dem ville stille fjernet
-- kontokoblinger. Slett dem eksplisitt før en nedrulling.
CREATE TABLE user_identities_old (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider     TEXT NOT NULL CHECK (provider IN ('google','microsoft','oidc')),
    issuer       TEXT NOT NULL,
    subject      TEXT NOT NULL,
    email        TEXT,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    last_used_at TEXT,
    admin_ok     INTEGER NOT NULL DEFAULT 0 CHECK (admin_ok IN (0,1)),
    UNIQUE (issuer, subject),
    CHECK (provider <> 'oidc' OR admin_ok = 0)
);
INSERT INTO user_identities_old (id, user_id, provider, issuer, subject, email, created_at, last_used_at, admin_ok)
SELECT id, user_id, provider, issuer, subject, email, created_at, last_used_at, admin_ok
FROM user_identities ORDER BY id;
DROP TABLE user_identities;
ALTER TABLE user_identities_old RENAME TO user_identities;
CREATE INDEX idx_user_identities_user ON user_identities(user_id);

-- Krever SQLite 3.35 eller nyere. Kolonnene inneholder bare konfig.
ALTER TABLE services DROP COLUMN github_client_secret_env;
ALTER TABLE services DROP COLUMN github_client_id;
ALTER TABLE services DROP COLUMN auth_github;
