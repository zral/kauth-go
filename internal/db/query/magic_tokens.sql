-- name: InsertMagicToken :exec
INSERT INTO magic_tokens (token, email, service_id, redirect_uri, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: ConsumeMagicToken :one
UPDATE magic_tokens
SET used = 1
WHERE token = ? AND used = 0 AND expires_at > ?
RETURNING *;

-- name: DeleteExpiredMagicTokens :exec
DELETE FROM magic_tokens
WHERE (used = 1 AND expires_at < ?)
   OR expires_at < ?;
