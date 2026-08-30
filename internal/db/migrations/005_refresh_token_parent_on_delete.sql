-- +goose Up
-- parent_id peker på refresh_tokens selv, men ble deklarert uten ON DELETE og
-- fikk dermed NO ACTION. Oppryddingsjobben sletter utløpte tokens i én DELETE;
-- så snart en utløpt forelder hadde et barn som ennå levde, feilet hele
-- setningen med FOREIGN KEY constraint failed (787) — og ingen tokens ble
-- slettet i det hele tatt. Tabellen vokste ubegrenset.
--
-- parent_id skrives i token/refresh.go, men leses ikke av noen spørring:
-- familie-revokering går på family_id. Feltet er et forensisk spor, så
-- SET NULL taper ingenting som brukes.

-- H2-migreringen satte inn rader med eksplisitte id-er og etterlot pekere til
-- forelder som aldri fulgte med. De må nulles før tabellen kan bygges om.
UPDATE refresh_tokens SET parent_id = NULL
WHERE parent_id IS NOT NULL
  AND parent_id NOT IN (SELECT id FROM refresh_tokens);

CREATE TABLE refresh_tokens_new (
    id                INTEGER PRIMARY KEY,
    token_hash        TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64),
    email             TEXT NOT NULL,
    service_id        TEXT REFERENCES services(id) ON DELETE SET NULL,
    family_id         TEXT NOT NULL,
    parent_id         INTEGER REFERENCES refresh_tokens_new(id) ON DELETE SET NULL,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    expires_at        TEXT NOT NULL,
    family_expires_at TEXT,
    used              INTEGER NOT NULL DEFAULT 0,
    revoked           INTEGER NOT NULL DEFAULT 0,
    revoked_reason    TEXT,
    ip_address        TEXT,
    user_agent        TEXT
);

-- ORDER BY id: FK-sjekken er umiddelbar, så forelderen må være satt inn før
-- barnet. Rotasjonskjeden gir alltid forelder lavere id enn barn.
INSERT INTO refresh_tokens_new
SELECT id, token_hash, email, service_id, family_id, parent_id, created_at,
       expires_at, family_expires_at, used, revoked, revoked_reason,
       ip_address, user_agent
FROM refresh_tokens ORDER BY id;

DROP TABLE refresh_tokens;
ALTER TABLE refresh_tokens_new RENAME TO refresh_tokens;

CREATE INDEX idx_refresh_tokens_family      ON refresh_tokens(family_id);
CREATE INDEX idx_refresh_tokens_expires     ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_fam_expires ON refresh_tokens(family_expires_at)
    WHERE family_expires_at IS NOT NULL;

-- +goose Down
-- Bygger tilbake til NO ACTION. De nullede foreldreløse pekerne kommer ikke
-- tilbake — hvilke rader de pekte på finnes ikke lenger noe sted.
CREATE TABLE refresh_tokens_old (
    id                INTEGER PRIMARY KEY,
    token_hash        TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64),
    email             TEXT NOT NULL,
    service_id        TEXT REFERENCES services(id) ON DELETE SET NULL,
    family_id         TEXT NOT NULL,
    parent_id         INTEGER REFERENCES refresh_tokens_old(id),
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
