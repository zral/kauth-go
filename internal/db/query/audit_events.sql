-- name: InsertAuditEvent :exec
INSERT INTO audit_events
    (event_type, auth_method, email, service_id, ip_address, user_agent, success, details, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListAuditEvents :many
SELECT * FROM audit_events
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: ListAuditEventsByEmail :many
SELECT * FROM audit_events
WHERE email = ?
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: ListAuditEventsByService :many
SELECT * FROM audit_events
WHERE service_id = ?
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: DeleteOldAuditEvents :exec
DELETE FROM audit_events WHERE created_at < ?;

-- name: CountAuditEvents :one
SELECT COUNT(*) FROM audit_events;
