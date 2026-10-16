-- Comments above queries must be ASCII only: sqlc has an offset bug that
-- corrupts the generated SQL otherwise.
-- All timestamps (created_at, expires_at, used_at, now, cutoff, window_start)
-- must be formatted %Y-%m-%dT%H:%M:%SZ (UTC, fixed width) because they are
-- compared as text.

-- Conditional insert: at most 5 invites per user in the window, counted on
-- created_at so burned rows still count.
-- name: InsertLinkInviteLimited :execrows
INSERT INTO identity_link_invites (token_hash, user_id, provider_id, service_id, email, created_by, created_at, expires_at)
SELECT CAST(sqlc.arg(token_hash) AS TEXT), CAST(sqlc.arg(user_id) AS INTEGER), CAST(sqlc.arg(provider_id) AS INTEGER), CAST(sqlc.arg(service_id) AS TEXT), CAST(sqlc.arg(email) AS TEXT), CAST(sqlc.arg(created_by) AS TEXT), CAST(sqlc.arg(created_at) AS TEXT), CAST(sqlc.arg(expires_at) AS TEXT)
WHERE (
    SELECT COUNT(*) FROM identity_link_invites
    WHERE identity_link_invites.user_id = sqlc.arg(user_id) AND identity_link_invites.created_at > sqlc.arg(window_start)
) < 5;

-- UPDATE, not DELETE: created_at must stay for the rate limit.
-- name: BurnLinkInvites :execrows
UPDATE identity_link_invites SET used_at = CAST(sqlc.arg(now) AS TEXT)
WHERE user_id = sqlc.arg(user_id) AND provider_id = sqlc.arg(provider_id) AND used_at IS NULL;

-- name: BurnLinkInvitesForUser :execrows
UPDATE identity_link_invites SET used_at = CAST(sqlc.arg(now) AS TEXT)
WHERE user_id = sqlc.arg(user_id) AND used_at IS NULL;

-- name: GetValidLinkInviteByHash :one
SELECT * FROM identity_link_invites
WHERE token_hash = sqlc.arg(token_hash) AND used_at IS NULL AND expires_at > sqlc.arg(now);

-- name: GetLinkInviteByID :one
SELECT * FROM identity_link_invites WHERE id = sqlc.arg(id);

-- Single conditional UPDATE so two concurrent callbacks cannot both win.
--
-- name: ConsumeLinkInvite :one
UPDATE identity_link_invites
SET used_at = CAST(sqlc.arg(now) AS TEXT)
WHERE id = sqlc.arg(id) AND provider_id = sqlc.arg(provider_id) AND service_id = sqlc.arg(service_id) AND used_at IS NULL AND expires_at > sqlc.arg(now)
RETURNING *;

-- name: RevokeLinkInvite :execrows
UPDATE identity_link_invites SET used_at = CAST(sqlc.arg(now) AS TEXT)
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND used_at IS NULL;

-- name: ListActiveLinkInvitesByUser :many
SELECT * FROM identity_link_invites
WHERE user_id = sqlc.arg(user_id) AND used_at IS NULL AND expires_at > sqlc.arg(now)
ORDER BY id;

-- name: DeleteExpiredLinkInvites :exec
DELETE FROM identity_link_invites WHERE expires_at < sqlc.arg(cutoff);
