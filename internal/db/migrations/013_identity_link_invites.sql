-- +goose Up
-- Brukerbevist kobling (016): en admin lager en engangsinvitasjon som lar en
-- eksisterende bruker koble en generisk OIDC-identitet til kontoen sin.

-- Bare SHA-256-hash av tokenet lagres, så et databaselekkasje ikke gir
-- brukbare lenker. email er brukerens e-post da invitasjonen ble laget: endres
-- den før bruk, skal invitasjonen avvises i stedet for å kobles til en konto
-- som har skiftet eier. CASCADE på alle tre fremmednøkler hindrer
-- foreldreløse invitasjoner. AUTOINCREMENT: en id gjenbrukes aldri, så en
-- gammel state med link=<id> kan ikke treffe en senere invitasjon.
-- used_at settes både ved kobling, tilbaketrekking og erstatning; raden
-- beholdes så kvoteteller (created_at) ikke faller bort ved brenning.
CREATE TABLE identity_link_invites (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash  TEXT NOT NULL UNIQUE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_id INTEGER NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    service_id  TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    used_at     TEXT
);
CREATE INDEX idx_link_invites_user ON identity_link_invites(user_id);

-- +goose Down
DROP TABLE identity_link_invites;
