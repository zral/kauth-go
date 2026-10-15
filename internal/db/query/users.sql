-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = ? LIMIT 1;

-- name: GetActiveUserByEmail :one
SELECT * FROM users WHERE email = ? AND deactivated_at IS NULL LIMIT 1;

-- name: GetActiveUserByPublicID :one
SELECT * FROM users WHERE public_id = ? AND deactivated_at IS NULL;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = ?;

-- name: GetActiveUserByID :one
SELECT * FROM users WHERE id = ? AND deactivated_at IS NULL;

-- name: CreateUser :one
INSERT INTO users (public_id, email, password_hash, name, roles, orgs, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: UpdateUserLastLogin :exec
UPDATE users SET last_login = ? WHERE email = ?;

-- Gammel e-post sjekkes i samme setning (AND email = ?), saa en samtidig endring
-- gir 0 rader i stedet for aa bli overskrevet. (ASCII only: sqlc offset bug.)
-- name: UpdateUserEmail :execrows
UPDATE users SET email = sqlc.arg(new_email), email_changed_at = sqlc.arg(email_changed_at)
WHERE id = sqlc.arg(id) AND email = sqlc.arg(old_email);

-- Binder admin-Google til brukeren bare en gang: 0 rader betyr at den allerede
-- er bundet. (ASCII only: sqlc offset bug.)
-- name: BindAdmin :execrows
UPDATE users SET admin_bound_at = ? WHERE id = ? AND admin_bound_at IS NULL;

-- name: UpdateUser :exec
UPDATE users SET name = ?, roles = ?, orgs = ? WHERE id = ?;

-- name: DeactivateUser :one
UPDATE users SET deactivated_at = ? WHERE id = ? RETURNING email;

-- name: ListUsers :many
SELECT * FROM users ORDER BY email LIMIT ? OFFSET ?;

-- name: ListUsersByOrg :many
SELECT * FROM users WHERE orgs LIKE ? ORDER BY email LIMIT ? OFFSET ?;

-- name: CountUsers :one
SELECT COUNT(*) FROM users;
