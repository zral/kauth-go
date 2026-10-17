package db

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

// snapshotIdentities leser alle kolonner i fast rekkefølge, så to tilstander kan sammenlignes ordrett.
func snapshotIdentities(t *testing.T, d *sql.DB) [][]any {
	t.Helper()
	rows, err := d.Query(`SELECT id,user_id,provider,issuer,subject,email,created_at,last_used_at,admin_ok FROM user_identities ORDER BY id`)
	require.NoError(t, err)
	defer rows.Close()
	var out [][]any
	for rows.Next() {
		var id, uid, admin int64
		var prov, iss, sub, created string
		var email, used *string
		require.NoError(t, rows.Scan(&id, &uid, &prov, &iss, &sub, &email, &created, &used, &admin))
		out = append(out, []any{id, uid, prov, iss, sub, email, created, used, admin})
	}
	require.NoError(t, rows.Err())
	return out
}

func TestMigration015_UpDownPreservesIdentities(t *testing.T) {
	d := openRaw(t)
	require.NoError(t, goose.UpTo(d, "migrations", 14))
	addService(t, d, "s1", 1)
	uid := insertUserV9(t, d, "a@x.no")
	_, err := d.Exec(`INSERT INTO user_identities (id,user_id,provider,issuer,subject,email,created_at,last_used_at,admin_ok) VALUES
		(3,?,'google','https://accounts.google.com','g1','a@x.no','2026-01-01T00:00:00Z','2026-02-01T00:00:00Z',1),
		(5,?,'microsoft','https://login.microsoftonline.com/t/v2.0','m1',NULL,'2026-01-02T00:00:00Z',NULL,0),
		(8,?,'oidc','https://idp.example','o1','o@x.no','2026-01-03T00:00:00Z',NULL,0)`, uid, uid, uid)
	require.NoError(t, err)
	before := snapshotIdentities(t, d)
	require.Len(t, before, 3)

	require.NoError(t, goose.UpTo(d, "migrations", 15))
	require.Equal(t, before, snapshotIdentities(t, d), "Up skal være tapsfri")
	// Services er additiv: eksisterende rad får av og ingen konfig.
	require.Equal(t, 1, count(t, d, `SELECT count(*) FROM services WHERE id='s1' AND auth_github=0 AND github_client_id IS NULL AND github_client_secret_env IS NULL`))
	require.Equal(t, 1, count(t, d, `SELECT count(*) FROM sqlite_master WHERE type='index' AND name='idx_user_identities_user'`))
	// UNIQUE(issuer, subject) er beholdt.
	_, err = d.Exec(`INSERT INTO user_identities (user_id,provider,issuer,subject) VALUES (?,'google','https://accounts.google.com','g1')`, uid)
	require.Error(t, err)
	require.Equal(t, 1, count(t, d, `SELECT count(*) FROM users`), "ingen kaskade under ombyggingen")

	require.NoError(t, goose.DownTo(d, "migrations", 14))
	require.Equal(t, int64(14), gooseVersion(t, d))
	require.Equal(t, before, snapshotIdentities(t, d), "Down skal være tapsfri uten github-rader")
	require.Equal(t, 0, count(t, d, `SELECT count(*) FROM pragma_table_info('services') WHERE name LIKE '%github%'`))
	require.Equal(t, 1, count(t, d, `SELECT count(*) FROM sqlite_master WHERE type='index' AND name='idx_user_identities_user'`))
	// 012-skjemaet er gjenskapt: github avvises igjen.
	_, err = d.Exec(`INSERT INTO user_identities (user_id,provider,issuer,subject) VALUES (?,'github','https://github.com','1')`, uid)
	require.Error(t, err)
}

func TestMigration015_DownFailsWithGitHubRow(t *testing.T) {
	d, _ := openMigrated(t)
	uid := insertUserV9(t, d, "a@x.no")
	_, err := d.Exec(`INSERT INTO user_identities (user_id,provider,issuer,subject) VALUES (?,'github','https://github.com','42')`, uid)
	require.NoError(t, err)

	require.Error(t, goose.DownTo(d, "migrations", 14))
	// Transaksjonen er rullet tilbake: raden og versjonen står.
	require.Equal(t, 1, count(t, d, `SELECT count(*) FROM user_identities WHERE provider='github'`))
	require.Equal(t, 1, count(t, d, `SELECT count(*) FROM pragma_table_info('services') WHERE name='auth_github'`))
}

func TestMigration015_Checks(t *testing.T) {
	d, _ := openMigrated(t)
	uid := insertUserV9(t, d, "a@x.no")
	ins := `INSERT INTO user_identities (user_id,provider,issuer,subject,admin_ok) VALUES (?,?,?,?,?)`

	_, err := d.Exec(ins, uid, "github", "https://github.com", "1", 0)
	require.NoError(t, err)
	_, err = d.Exec(ins, uid, "github", "https://github.com", "2", 1)
	require.Error(t, err, "admin_ok=1 for github")
	_, err = d.Exec(ins, uid, "oidc", "https://idp.example", "1", 1)
	require.Error(t, err, "admin_ok=1 for oidc")
	_, err = d.Exec(ins, uid, "google", "https://accounts.google.com", "1", 1)
	require.NoError(t, err, "google beholder admin_ok")
	_, err = d.Exec(ins, uid, "gitlab", "https://gitlab.com", "1", 0)
	require.Error(t, err, "ukjent provider")

	addService(t, d, "s1", 1)
	_, err = d.Exec(`UPDATE services SET auth_github=2 WHERE id='s1'`)
	require.Error(t, err)
	_, err = d.Exec(`UPDATE services SET auth_github=1, github_client_id='Iv1.abc' WHERE id='s1'`)
	require.NoError(t, err)
	for val, ok := range map[string]bool{
		"KAUTH_SVC_GH_SECRET":   true,
		"KAUTH_IDP_ACME":        false,
		"KAUTH_PRIVATE_KEY_PEM": false,
		"kauth_svc_gh":          false,
		"KAUTH_SVC_GH-X":        false,
		"KAUTH_SVC_":            false,
		"":                      false,
	} {
		_, err := d.Exec(`UPDATE services SET github_client_secret_env=? WHERE id='s1'`, val)
		if ok {
			require.NoError(t, err, val)
		} else {
			require.Error(t, err, val)
		}
	}
	_, err = d.Exec(`UPDATE services SET github_client_secret_env=NULL WHERE id='s1'`)
	require.NoError(t, err)
}
