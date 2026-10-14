package db

import (
	"context"
	"database/sql"
	"regexp"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func gooseVersion(t *testing.T, d *sql.DB) int64 {
	t.Helper()
	v, err := goose.GetDBVersion(d)
	require.NoError(t, err)
	return v
}

func insertUserV9(t *testing.T, d *sql.DB, email string) int64 {
	t.Helper()
	res, err := d.Exec(`INSERT INTO users (email,roles,orgs,created_at) VALUES (?, 'user','o','2026-01-01T00:00:00Z')`, email)
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

func TestMigration011_Backfill(t *testing.T) {
	d := openRaw(t)
	require.NoError(t, goose.UpTo(d, "migrations", 9))
	type userRow struct {
		ID                                 int64
		Email                              string
		Hash, Name, LastLogin, Deactivated sql.NullString
		Roles, Orgs, CreatedAt             string
	}
	want := []userRow{
		{Email: "a@x.no", Hash: sql.NullString{String: "pw1", Valid: true}, Name: sql.NullString{String: "Anne", Valid: true},
			Roles: "user,konge", Orgs: "o1,o2", CreatedAt: "2026-01-02T03:04:05Z",
			LastLogin: sql.NullString{String: "2026-02-03T04:05:06Z", Valid: true}},
		{Email: "b@x.no", Roles: "user", Orgs: "o1", CreatedAt: "2026-01-03T00:00:00Z",
			Deactivated: sql.NullString{String: "2026-03-01T00:00:00Z", Valid: true}},
		{Email: "c@x.no", Roles: "", Orgs: "", CreatedAt: "2026-01-04T00:00:00Z"},
	}
	ids := map[string]int64{}
	for i := range want {
		w := &want[i]
		res, err := d.Exec(`INSERT INTO users (email,password_hash,name,roles,orgs,created_at,last_login,deactivated_at) VALUES (?,?,?,?,?,?,?,?)`,
			w.Email, w.Hash, w.Name, w.Roles, w.Orgs, w.CreatedAt, w.LastLogin, w.Deactivated)
		require.NoError(t, err)
		w.ID, err = res.LastInsertId()
		require.NoError(t, err)
		ids[w.Email] = w.ID
	}
	_, err := d.Exec(`INSERT INTO services (id,display_name,domain,callback_url,email_from_name,updated_at) VALUES ('s','S','s.no','https://s.no/cb','S','2026-01-01T00:00:00Z')`)
	require.NoError(t, err)
	// Blandet case i sesjons- og kode-radene: backfill går på lower(trim(email)).
	_, err = d.Exec(`INSERT INTO refresh_tokens (token_hash,email,service_id,family_id,expires_at) VALUES (?, 'A@X.no ', 's', 'f1', '2099-01-01T00:00:00Z')`, "1111111111111111111111111111111111111111111111111111111111111111")
	require.NoError(t, err)
	_, err = d.Exec(`INSERT INTO refresh_tokens (token_hash,email,service_id,family_id,expires_at) VALUES (?, 'ukjent@x.no', 's', 'f2', '2099-01-01T00:00:00Z')`, "2222222222222222222222222222222222222222222222222222222222222222")
	require.NoError(t, err)
	_, err = d.Exec(`INSERT INTO authorization_codes (code,service_id,email,redirect_uri,code_challenge,code_challenge_method,expires_at) VALUES ('h','s','B@x.no','https://s.no/cb','c','S256','2099-01-01T00:00:00Z')`)
	require.NoError(t, err)

	require.NoError(t, goose.UpTo(d, "migrations", 10))

	seen := map[string]bool{}
	rows, err := d.Query(`SELECT id, email, password_hash, name, roles, orgs, created_at, last_login, deactivated_at, public_id FROM users ORDER BY id`)
	require.NoError(t, err)
	defer rows.Close()
	n := 0
	for rows.Next() {
		var got userRow
		var pub string
		require.NoError(t, rows.Scan(&got.ID, &got.Email, &got.Hash, &got.Name, &got.Roles, &got.Orgs, &got.CreatedAt, &got.LastLogin, &got.Deactivated, &pub))
		require.Equal(t, want[n], got, "alle kolonner bevares rad for rad")
		require.Regexp(t, uuidV4, pub)
		require.False(t, seen[pub], "public_id er unik")
		seen[pub] = true
		n++
	}
	require.Equal(t, 3, n)

	var uid sql.NullInt64
	require.NoError(t, d.QueryRow(`SELECT user_id FROM refresh_tokens WHERE family_id='f1'`).Scan(&uid))
	require.Equal(t, ids["a@x.no"], uid.Int64)
	require.NoError(t, d.QueryRow(`SELECT user_id FROM refresh_tokens WHERE family_id='f2'`).Scan(&uid))
	require.False(t, uid.Valid, "rad uten e-postmatch beholder NULL")
	require.NoError(t, d.QueryRow(`SELECT user_id FROM authorization_codes`).Scan(&uid))
	require.Equal(t, ids["b@x.no"], uid.Int64)

	var sf string
	var al int64
	require.NoError(t, d.QueryRow(`SELECT sub_format, auto_link FROM services WHERE id='s'`).Scan(&sf, &al))
	require.Equal(t, "email", sf)
	require.EqualValues(t, 1, al)

	require.True(t, hasIndex(t, d, "idx_users_email_norm"))
	require.True(t, hasIndex(t, d, "idx_refresh_tokens_user"))
	require.True(t, hasIndex(t, d, "idx_user_identities_user"))
}

func TestMigration011_GuardRejects(t *testing.T) {
	for _, bad := range []string{"Ø@x.no", "A@x.no", " a@x.no", "æ@x.no"} {
		t.Run(bad, func(t *testing.T) {
			d := openRaw(t)
			require.NoError(t, goose.UpTo(d, "migrations", 9))
			insertUserV9(t, d, "ok@x.no")
			insertUserV9(t, d, bad)

			require.Error(t, goose.UpTo(d, "migrations", 10))
			require.EqualValues(t, 9, gooseVersion(t, d))
			require.False(t, hasColumn(t, d, "users", "public_id"), "users er uendret")
			var n int
			require.NoError(t, d.QueryRow(`SELECT count(*) FROM users`).Scan(&n))
			require.Equal(t, 2, n)
			require.NoError(t, d.QueryRow(`SELECT count(*) FROM sqlite_temp_master WHERE name='_guard_011'`).Scan(&n))
			require.Zero(t, n, "vakt-tabellen ruller tilbake")
		})
	}
}

func TestMigration011_DownUp(t *testing.T) {
	d := openRaw(t)
	require.NoError(t, goose.UpTo(d, "migrations", 9))
	a := insertUserV9(t, d, "a@x.no")
	_, err := d.Exec(`INSERT INTO services (id,display_name,domain,callback_url,email_from_name,updated_at) VALUES ('s','S','s.no','https://s.no/cb','S','2026-01-01T00:00:00Z')`)
	require.NoError(t, err)
	_, err = d.Exec(`INSERT INTO refresh_tokens (token_hash,email,service_id,family_id,expires_at) VALUES (?, 'a@x.no', 's', 'f1', '2099-01-01T00:00:00Z')`, "1111111111111111111111111111111111111111111111111111111111111111")
	require.NoError(t, err)
	require.NoError(t, goose.UpTo(d, "migrations", 10))
	_, err = d.Exec(`INSERT INTO user_identities (user_id,provider,issuer,subject) VALUES (?, 'google','https://accounts.google.com','s1')`, a)
	require.NoError(t, err)

	require.NoError(t, goose.DownTo(d, "migrations", 9))
	require.EqualValues(t, 9, gooseVersion(t, d))
	require.False(t, hasColumn(t, d, "users", "public_id"))
	require.False(t, hasColumn(t, d, "refresh_tokens", "user_id"))
	require.False(t, hasColumn(t, d, "authorization_codes", "user_id"))
	require.False(t, hasColumn(t, d, "services", "sub_format"))
	require.False(t, hasColumn(t, d, "services", "auto_link"))
	require.True(t, hasColumn(t, d, "authorization_codes", "family_id"))
	require.True(t, hasIndex(t, d, "idx_users_email_norm"))
	require.True(t, hasIndex(t, d, "idx_refresh_tokens_family"))
	require.True(t, hasIndex(t, d, "idx_authorization_codes_expires"))
	require.False(t, hasIndex(t, d, "idx_refresh_tokens_user"))
	var n int
	require.NoError(t, d.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name='user_identities'`).Scan(&n))
	require.Zero(t, n)
	require.NoError(t, d.QueryRow(`SELECT count(*) FROM users WHERE id=?`, a).Scan(&n))
	require.Equal(t, 1, n, "data bevares")
	require.NoError(t, d.QueryRow(`SELECT count(*) FROM refresh_tokens`).Scan(&n))
	require.Equal(t, 1, n)

	require.NoError(t, goose.UpTo(d, "migrations", 10))
	var uid sql.NullInt64
	require.NoError(t, d.QueryRow(`SELECT user_id FROM refresh_tokens`).Scan(&uid))
	require.Equal(t, a, uid.Int64)
	var viol int
	rows, err := d.Query(`PRAGMA foreign_key_check`)
	require.NoError(t, err)
	for rows.Next() {
		viol++
	}
	require.NoError(t, rows.Close())
	require.Zero(t, viol)
}

func TestUserIdentity_UniqueIssuerSubject(t *testing.T) {
	sqldb, q, err := OpenMemory()
	require.NoError(t, err)
	defer sqldb.Close()
	ctx := context.Background()
	u, err := q.CreateUser(ctx, gen.CreateUserParams{PublicID: token.MustNewPublicID(), Email: "a@x.no", Roles: "user", CreatedAt: "2026-01-01T00:00:00Z"})
	require.NoError(t, err)
	v, err := q.CreateUser(ctx, gen.CreateUserParams{PublicID: token.MustNewPublicID(), Email: "b@x.no", Roles: "user", CreatedAt: "2026-01-01T00:00:00Z"})
	require.NoError(t, err)

	p := gen.InsertIdentityParams{UserID: u.ID, Provider: "google", Issuer: "https://accounts.google.com", Subject: "s1", CreatedAt: "2026-01-01T00:00:00Z"}
	n, err := q.InsertIdentity(ctx, p)
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	p.UserID = v.ID
	n, err = q.InsertIdentity(ctx, p)
	require.NoError(t, err)
	require.EqualValues(t, 0, n, "ON CONFLICT DO NOTHING")

	var cnt int
	require.NoError(t, sqldb.QueryRow(`SELECT count(*) FROM user_identities`).Scan(&cnt))
	require.Equal(t, 1, cnt)
	got, err := q.GetIdentity(ctx, gen.GetIdentityParams{Issuer: p.Issuer, Subject: "s1"})
	require.NoError(t, err)
	require.Equal(t, u.ID, got.UserID, "vinneren beholder identiteten")

	ok, err := q.HasIdentity(ctx, u.ID)
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = q.HasIdentity(ctx, v.ID)
	require.NoError(t, err)
	require.False(t, ok)
	list, err := q.ListIdentitiesByUser(ctx, u.ID)
	require.NoError(t, err)
	require.Len(t, list, 1)
}

func TestCreateUser_DefaultPublicID(t *testing.T) {
	sqldb, q, err := OpenMemory()
	require.NoError(t, err)
	defer sqldb.Close()
	ctx := context.Background()
	seen := map[string]bool{}
	for _, e := range []string{"a@x.no", "b@x.no", "c@x.no", "d@x.no"} {
		// Rå INSERT uten public_id: seed-SQL og H2-import går denne stien.
		// CreateUser setter nå alltid verdien selv.
		_, err := sqldb.ExecContext(ctx, `INSERT INTO users (email, roles, created_at) VALUES (?, 'user', '2026-01-01T00:00:00Z')`, e)
		require.NoError(t, err)
		u, err := q.GetUserByEmail(ctx, e)
		require.NoError(t, err)
		require.Regexp(t, uuidV4, u.PublicID)
		require.False(t, seen[u.PublicID])
		seen[u.PublicID] = true
	}
}
