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
