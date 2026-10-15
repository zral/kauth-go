-- +goose Up
-- Admin-identitet (012): e-postepoke og engangsbinding av admin-Google.

-- email_changed_at: tidspunktet brukeren fikk sin nåværende e-post. NULL
-- betyr at adressen er den opprinnelige (epoken er da created_at).
ALTER TABLE users ADD COLUMN email_changed_at TEXT;

-- admin_bound_at: settes én gang når admin-Google godkjennes, og nullstilles
-- aldri av frakobling. Uten den ville en frakoblet admin_ok-identitet gjort
-- kontoen åpen for en ny godkjenning.
ALTER TABLE users ADD COLUMN admin_bound_at TEXT;

-- Brukere som allerede har en godkjent admin-identitet regnes som bundet fra
-- migrasjonstidspunktet. Ubundne konge-brukere forblir ubundne (første
-- admin-Google binder dem som før).
UPDATE users SET admin_bound_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
WHERE id IN (SELECT user_id FROM user_identities WHERE admin_ok = 1);

-- +goose Down
-- Kolonnene har verken FK eller indeks, så DROP COLUMN er trygt (SQLite >= 3.35).
-- Down er ikke tapsfri etter at frakobling er i bruk: en ny Up binder bare
-- brukere som fortsatt har en admin_ok-identitet, så en bruker som har fått
-- admin-identiteten koblet fra, blir åpen for en ny første admin-Google.
-- Rull tilbake binæren, ikke migrasjonen.
ALTER TABLE users DROP COLUMN admin_bound_at;
ALTER TABLE users DROP COLUMN email_changed_at;
