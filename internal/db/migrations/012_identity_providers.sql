-- +goose Up
-- Generisk OIDC (015): konfigurerbare identitetsleverandører per tjeneste, og
-- user_identities får en tredje provider-verdi, 'oidc'.

-- CHECK-ene under er forsvar i dybden: lastevalideringen i kode er autoritativ,
-- men en feilkonfigurert rad (satt inn med sqlite3 for hånd) skal heller
-- avvises av databasen enn å åpne for utgiverforveksling eller lekke hemmeligheter.
-- Hver leverandør er en rad. issuer er UNIQUE fordi (issuer, subject) er
-- identitetsnøkkelen i user_identities: to rader med samme issuer ville latt
-- ulike konfigurasjoner dele identiteter. Hemmeligheten lagres aldri her,
-- bare navnet på miljøvariabelen som holder den.
-- AUTOINCREMENT: en id gjenbrukes aldri. sqlite3-CLI har foreign_keys av, så en
-- manuell DELETE kan etterlate en tilordning; uten AUTOINCREMENT ville neste
-- leverandør fått samme id og stille arvet tilordningen til en annen tjeneste.
CREATE TABLE identity_providers (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    slug              TEXT NOT NULL UNIQUE
        CHECK (length(slug) BETWEEN 1 AND 32 AND slug NOT GLOB '*[^a-z0-9-]*'),
    display_name      TEXT NOT NULL,
    -- Google og Microsoft har egne flyter med egne issuer-regler; en generisk
    -- rad med deres issuer ville latt en annen konfigurasjon utgi seg for dem.
    issuer            TEXT NOT NULL UNIQUE
        CHECK (issuer NOT IN ('https://accounts.google.com','accounts.google.com')
           AND issuer NOT LIKE 'https://login.microsoftonline.com/%'
           AND issuer NOT LIKE 'https://sts.windows.net/%'
           AND issuer NOT LIKE 'https://login.live.com%'),
    client_id         TEXT NOT NULL,
    -- Bare navn med prefikset KAUTH_IDP_ kan refereres, så en rad ikke kan peke
    -- på KAUTH_PRIVATE_KEY_PEM eller andre interne hemmeligheter.
    client_secret_env TEXT
        CHECK (client_secret_env IS NULL OR
               (client_secret_env GLOB 'KAUTH_IDP_[A-Z0-9_]*'
                AND client_secret_env NOT GLOB '*[^A-Z0-9_]*')),
    scopes            TEXT NOT NULL DEFAULT 'openid email profile',
    trust_email       INTEGER NOT NULL DEFAULT 0 CHECK (trust_email IN (0,1)),
    email_domains     TEXT NOT NULL DEFAULT '',
    active            INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    -- Tillit til e-post uten domeneliste ville latt enhver konto hos
    -- leverandøren kobles til en eksisterende bruker.
    CHECK (trust_email = 0 OR email_domains <> '')
);

-- Tilordningen er datadrevet, så en leverandør bare vises for tjenestene som
-- eksplisitt har den. CASCADE begge veier hindrer foreldreløse rader.
CREATE TABLE service_identity_providers (
    service_id  TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    provider_id INTEGER NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    position    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (service_id, provider_id)
);

-- SQLite kan ikke endre en CHECK, så user_identities bygges om. Ingen tabell
-- refererer til user_identities (den peker bare på users), så DROP trigger
-- ingen ON DELETE CASCADE hos andre, selv om foreign_keys er på. Goose kjører
-- hele filen i én transaksjon, der PRAGMA foreign_keys uansett er en no-op.
CREATE TABLE user_identities_new (
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
    -- En generisk identitet skal aldri gi admin-innlogging.
    CHECK (provider <> 'oidc' OR admin_ok = 0)
);

INSERT INTO user_identities_new (id, user_id, provider, issuer, subject, email, created_at, last_used_at, admin_ok)
SELECT id, user_id, provider, issuer, subject, email, created_at, last_used_at, admin_ok
FROM user_identities ORDER BY id;

-- Vakt: ombyggingen skal ikke miste eller duplisere en eneste identitet.
-- CHECK-bruddet ruller tilbake hele goose-transaksjonen.
CREATE TEMP TABLE _guard_012 (n INTEGER CHECK (n = 0));
INSERT INTO _guard_012
SELECT (SELECT count(*) FROM user_identities) - (SELECT count(*) FROM user_identities_new);
DROP TABLE _guard_012;

DROP TABLE user_identities;
ALTER TABLE user_identities_new RENAME TO user_identities;
CREATE INDEX idx_user_identities_user ON user_identities(user_id);

-- +goose Down
-- Feiler med vilje på CHECK hvis det finnes provider='oidc'-rader: de kan ikke
-- representeres i det gamle skjemaet, og å slette dem ville stille fjernet
-- kontokoblinger. Slett dem eksplisitt før en nedrulling.
DROP TABLE service_identity_providers;
DROP TABLE identity_providers;

CREATE TABLE user_identities_old (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider     TEXT NOT NULL CHECK (provider IN ('google','microsoft')),
    issuer       TEXT NOT NULL,
    subject      TEXT NOT NULL,
    email        TEXT,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    last_used_at TEXT,
    admin_ok     INTEGER NOT NULL DEFAULT 0 CHECK (admin_ok IN (0,1)),
    UNIQUE (issuer, subject)
);
INSERT INTO user_identities_old (id, user_id, provider, issuer, subject, email, created_at, last_used_at, admin_ok)
SELECT id, user_id, provider, issuer, subject, email, created_at, last_used_at, admin_ok
FROM user_identities ORDER BY id;
DROP TABLE user_identities;
ALTER TABLE user_identities_old RENAME TO user_identities;
CREATE INDEX idx_user_identities_user ON user_identities(user_id);
