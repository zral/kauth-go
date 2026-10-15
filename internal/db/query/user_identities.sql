-- name: GetIdentity :one
SELECT * FROM user_identities WHERE issuer = ? AND subject = ?;

-- DO NOTHING: concurrent first logins with the same identity yield one row;
-- the loser reads back the winner's row. (ASCII only: sqlc offset bug.)
-- name: InsertIdentity :execrows
INSERT INTO user_identities (user_id, provider, issuer, subject, email, created_at, last_used_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (issuer, subject) DO NOTHING;

-- name: UpdateIdentitySeen :exec
UPDATE user_identities SET email = ?, last_used_at = ? WHERE id = ?;

-- name: HasIdentity :one
SELECT EXISTS (SELECT 1 FROM user_identities WHERE user_id = ?);

-- name: ListIdentitiesByUser :many
SELECT * FROM user_identities WHERE user_id = ? ORDER BY created_at, id;

-- Betinget kobling for auto_link=0: INSERT og vilkaret (brukeren har ingen
-- identitet) er ett atomisk utsagn, ellers kan to ulike kontoer koble seg
-- samtidig. (ASCII only: sqlc offset bug.)
-- name: LinkIdentityIfFirst :execrows
INSERT INTO user_identities (user_id, provider, issuer, subject, email, created_at, last_used_at)
SELECT ?, ?, ?, ?, ?, ?, ?
WHERE NOT EXISTS (SELECT 1 FROM user_identities ex WHERE ex.user_id = ?)
ON CONFLICT (issuer, subject) DO NOTHING;

-- AND user_id = ? hindrer at en admin sletter en annen brukers identitet.
-- RETURNING gir audit-feltene fra raden som faktisk ble slettet.
-- (ASCII only: sqlc offset bug.)
-- name: DeleteIdentity :one
DELETE FROM user_identities WHERE id = ? AND user_id = ?
RETURNING provider, issuer, admin_ok;

-- name: SetAdminOK :execrows
UPDATE user_identities SET admin_ok = 1 WHERE id = ? AND user_id = ?;

-- Godkjenner identiteten for admin bare hvis brukeren ikke har en godkjent fra for.
-- name: ApproveAdminIdentity :execrows
UPDATE user_identities SET admin_ok = 1
WHERE user_identities.id = ? AND user_identities.user_id = ?
  AND NOT EXISTS (SELECT 1 FROM user_identities ex WHERE ex.user_id = ? AND ex.admin_ok = 1);
