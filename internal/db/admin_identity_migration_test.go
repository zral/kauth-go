package db

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

const userColsV10 = `id, email, password_hash, name, roles, orgs, created_at, last_login, deactivated_at, public_id`

func dumpUsersV10(t *testing.T, d *sql.DB) [][]sql.NullString {
	t.Helper()
	rows, err := d.Query(`SELECT ` + userColsV10 + ` FROM users ORDER BY id`)
	require.NoError(t, err)
	defer rows.Close()
	var out [][]sql.NullString
	for rows.Next() {
		r := make([]sql.NullString, 10)
		ptrs := make([]any, 10)
		for i := range r {
			ptrs[i] = &r[i]
		}
		require.NoError(t, rows.Scan(ptrs...))
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out
}

// K1: bare brukere med en admin_ok-identitet får admin_bound_at. Ubundne
// konge-brukere forblir ubundne, og alle andre kolonner står uendret.
func TestMigration012_BackfillAdminBound(t *testing.T) {
	d := openRaw(t)
	require.NoError(t, goose.UpTo(d, "migrations", 10))

	mk := func(email, roles string) int64 {
		res, err := d.Exec(`INSERT INTO users (email,roles,orgs,created_at,name) VALUES (?, ?, 'o','2026-01-01T00:00:00Z','N')`, email, roles)
		require.NoError(t, err)
		id, err := res.LastInsertId()
		require.NoError(t, err)
		return id
	}
	approved := mk("approved@x.no", "user,konge")
	unapproved := mk("unapproved@x.no", "user,konge")
	noIdentity := mk("none@x.no", "user,konge")
	plain := mk("plain@x.no", "user")
	ident := func(uid int64, subject string, adminOK int) {
		_, err := d.Exec(`INSERT INTO user_identities (user_id,provider,issuer,subject,admin_ok) VALUES (?, 'google','https://accounts.google.com',?,?)`, uid, subject, adminOK)
		require.NoError(t, err)
	}
	ident(approved, "s1", 1)
	ident(unapproved, "s2", 0)

	before := dumpUsersV10(t, d)
	require.NoError(t, goose.UpTo(d, "migrations", 11))
	require.EqualValues(t, 11, gooseVersion(t, d))
	require.Equal(t, before, dumpUsersV10(t, d), "alle eksisterende kolonner bevares rad for rad")

	bound := func(id int64) sql.NullString {
		var s sql.NullString
		require.NoError(t, d.QueryRow(`SELECT admin_bound_at FROM users WHERE id=?`, id).Scan(&s))
		return s
	}
	got := bound(approved)
	require.True(t, got.Valid)
	require.Regexp(t, `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`, got.String)
	require.False(t, bound(unapproved).Valid)
	require.False(t, bound(noIdentity).Valid)
	require.False(t, bound(plain).Valid)

	var n int
	require.NoError(t, d.QueryRow(`SELECT count(*) FROM users WHERE email_changed_at IS NOT NULL`).Scan(&n))
	require.Zero(t, n, "ingen har e-postepoke ennå")
}

func TestMigration012_DownUp(t *testing.T) {
	d := openRaw(t)
	require.NoError(t, goose.UpTo(d, "migrations", 11))
	id := insertUserV9(t, d, "a@x.no")
	_, err := d.Exec(`UPDATE users SET email_changed_at='2026-02-01T00:00:00Z', admin_bound_at='2026-02-01T00:00:00Z' WHERE id=?`, id)
	require.NoError(t, err)

	require.NoError(t, goose.DownTo(d, "migrations", 10))
	require.EqualValues(t, 10, gooseVersion(t, d))
	require.False(t, hasColumn(t, d, "users", "email_changed_at"))
	require.False(t, hasColumn(t, d, "users", "admin_bound_at"))
	require.True(t, hasColumn(t, d, "users", "public_id"))
	var n int
	require.NoError(t, d.QueryRow(`SELECT count(*) FROM users WHERE id=?`, id).Scan(&n))
	require.Equal(t, 1, n, "data bevares")

	require.NoError(t, goose.UpTo(d, "migrations", 11))
	require.EqualValues(t, 11, gooseVersion(t, d))
	require.True(t, hasColumn(t, d, "users", "email_changed_at"))
	require.True(t, hasColumn(t, d, "users", "admin_bound_at"))
	require.NoError(t, d.QueryRow(`SELECT count(*) FROM users WHERE email_changed_at IS NOT NULL OR admin_bound_at IS NOT NULL`).Scan(&n))
	require.Zero(t, n)
}
