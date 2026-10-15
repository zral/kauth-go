-- +goose Up
-- Stabil identitet (011): users får en uforanderlig public_id, føderert
-- innlogging får en egen identitetstabell, og sesjoner/koder får user_id.

-- Vakt: e-postoppslag blir eksakte (email = ?) og forutsetter at alle
-- lagrede adresser allerede er normalisert. En avvikende rad ville blitt
-- usynlig for innlogging, så migrasjonen skal heller feile enn å gå videre.
-- CHECK-bruddet ruller tilbake hele goose-transaksjonen.
CREATE TEMP TABLE _guard_011 (n INTEGER CHECK (n = 0));
INSERT INTO _guard_011
SELECT count(*) FROM users
WHERE email <> lower(trim(email)) OR email GLOB '*[^ -~]*';
DROP TABLE _guard_011;

-- users bygges om slik at public_id kan være NOT NULL UNIQUE. ALTER TABLE
-- ADD COLUMN tillater verken UNIQUE eller et uttrykk med randomblob som
-- default. Ingen tabell refererer til users ennå, så DROP/RENAME er trygt.
-- Default-uttrykket (UUID v4) fyller eksisterende rader og er hovedstien for
-- nye brukere til F2 lar Go sette verdien selv med crypto/rand; etter det er
-- det backstop for seed-SQL og tester.
CREATE TABLE users_new (
    id              INTEGER PRIMARY KEY,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT,
    name            TEXT,
    roles           TEXT NOT NULL DEFAULT '',
    orgs            TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    last_login      TEXT,
    deactivated_at  TEXT,
    public_id       TEXT NOT NULL UNIQUE DEFAULT (
        lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' ||
        substr(lower(hex(randomblob(2))), 2) || '-' ||
        substr('89ab', abs(random()) % 4 + 1, 1) ||
        substr(lower(hex(randomblob(2))), 2) || '-' || lower(hex(randomblob(6))))
);

INSERT INTO users_new (id, email, password_hash, name, roles, orgs, created_at, last_login, deactivated_at)
SELECT id, email, password_hash, name, roles, orgs, created_at, last_login, deactivated_at
FROM users ORDER BY id;

DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

CREATE UNIQUE INDEX idx_users_email_norm ON users(lower(trim(email)));

CREATE TABLE user_identities (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider     TEXT NOT NULL CHECK (provider IN ('google','microsoft')),
    issuer       TEXT NOT NULL,
    subject      TEXT NOT NULL,
    email        TEXT,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    last_used_at TEXT,
    -- Admin-godkjent identitet: koblinger er globale, så bare en eksplisitt
    -- godkjent identitet gir admin-innlogging (maks én per bruker).
    admin_ok     INTEGER NOT NULL DEFAULT 0 CHECK (admin_ok IN (0,1)),
    UNIQUE (issuer, subject)
);
CREATE INDEX idx_user_identities_user ON user_identities(user_id);

-- Nullable: rader uten e-postmatch (slettede brukere) beholder user_id NULL
-- og faller tilbake til e-post i token-laget.
ALTER TABLE refresh_tokens ADD COLUMN user_id INTEGER REFERENCES users(id);
ALTER TABLE authorization_codes ADD COLUMN user_id INTEGER REFERENCES users(id);

UPDATE refresh_tokens SET user_id =
    (SELECT u.id FROM users u WHERE lower(trim(u.email)) = lower(trim(refresh_tokens.email)));
UPDATE authorization_codes SET user_id =
    (SELECT u.id FROM users u WHERE lower(trim(u.email)) = lower(trim(authorization_codes.email)));

CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);

ALTER TABLE services ADD COLUMN sub_format TEXT NOT NULL DEFAULT 'email' CHECK (sub_format IN ('email','id'));
ALTER TABLE services ADD COLUMN auto_link INTEGER NOT NULL DEFAULT 1 CHECK (auto_link IN (0,1));

-- +goose Down
-- Down er ikke tapsfri: public_id, user_identities og user_id-koblingene
-- kommer ikke tilbake. En ny Up gir NYE public_id, og det endrer sub for
-- tjenester med sub_format=id. user_id fylles igjen via e-post, men
-- identitetskoblinger (issuer, subject) må bygges opp på nytt gjennom innlogging.
-- SQLite nekter DROP COLUMN på kolonner med FOREIGN KEY, så tabellene bygges
-- om. Tabellene som peker på users må være ombygget før users selv.
ALTER TABLE services DROP COLUMN auto_link;
ALTER TABLE services DROP COLUMN sub_format;

DROP TABLE user_identities;

CREATE TABLE refresh_tokens_old (
    id                INTEGER PRIMARY KEY,
    token_hash        TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64),
    email             TEXT NOT NULL,
    service_id        TEXT REFERENCES services(id) ON DELETE SET NULL,
    family_id         TEXT NOT NULL,
    parent_id         INTEGER REFERENCES refresh_tokens_old(id) ON DELETE SET NULL,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    expires_at        TEXT NOT NULL,
    family_expires_at TEXT,
    used              INTEGER NOT NULL DEFAULT 0,
    revoked           INTEGER NOT NULL DEFAULT 0,
    revoked_reason    TEXT,
    ip_address        TEXT,
    user_agent        TEXT
);
INSERT INTO refresh_tokens_old
SELECT id, token_hash, email, service_id, family_id, parent_id, created_at,
       expires_at, family_expires_at, used, revoked, revoked_reason,
       ip_address, user_agent
FROM refresh_tokens ORDER BY id;
DROP TABLE refresh_tokens;
ALTER TABLE refresh_tokens_old RENAME TO refresh_tokens;
CREATE INDEX idx_refresh_tokens_family      ON refresh_tokens(family_id);
CREATE INDEX idx_refresh_tokens_expires     ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_fam_expires ON refresh_tokens(family_expires_at)
    WHERE family_expires_at IS NOT NULL;

CREATE TABLE authorization_codes_old (
    id                    INTEGER PRIMARY KEY,
    code                  TEXT NOT NULL UNIQUE,
    service_id            TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    email                 TEXT NOT NULL,
    redirect_uri          TEXT NOT NULL,
    scope                 TEXT,
    nonce                 TEXT,
    code_challenge        TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    expires_at            TEXT NOT NULL,
    used                  INTEGER NOT NULL DEFAULT 0,
    family_id             TEXT
);
INSERT INTO authorization_codes_old
SELECT id, code, service_id, email, redirect_uri, scope, nonce, code_challenge,
       code_challenge_method, created_at, expires_at, used, family_id
FROM authorization_codes ORDER BY id;
DROP TABLE authorization_codes;
ALTER TABLE authorization_codes_old RENAME TO authorization_codes;
CREATE INDEX idx_authorization_codes_expires ON authorization_codes(expires_at);

CREATE TABLE users_old (
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
INSERT INTO users_old
SELECT id, email, password_hash, name, roles, orgs, created_at, last_login, deactivated_at
FROM users ORDER BY id;
DROP TABLE users;
ALTER TABLE users_old RENAME TO users;
CREATE UNIQUE INDEX idx_users_email_norm ON users(lower(trim(email)));
