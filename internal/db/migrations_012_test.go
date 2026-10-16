package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
	"github.com/zral/kauth-go/internal/db/gen"
)

func openMigrated(t *testing.T) (*sql.DB, *gen.Queries) {
	t.Helper()
	d := openRaw(t)
	require.NoError(t, goose.Up(d, "migrations"))
	return d, gen.New(d)
}

const svcInsert = `INSERT INTO services (id,display_name,domain,callback_url,email_from_name,updated_at,active) VALUES (?,?,?,?,'S','2026-01-01T00:00:00Z',?)`

func addService(t *testing.T, d *sql.DB, id string, active int) {
	t.Helper()
	_, err := d.Exec(svcInsert, id, id, id+".no", "https://"+id+".no/cb", active)
	require.NoError(t, err)
}

func addProvider(t *testing.T, d *sql.DB, slug string, active int) int64 {
	t.Helper()
	res, err := d.Exec(`INSERT INTO identity_providers (slug,display_name,issuer,client_id,active) VALUES (?,?,?,?,?)`,
		slug, slug, "https://"+slug+".example", "cid", active)
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

func count(t *testing.T, d *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, d.QueryRow(q, args...).Scan(&n))
	return n
}

func TestMigration012_PreservesIdentities(t *testing.T) {
	d := openRaw(t)
	require.NoError(t, goose.UpTo(d, "migrations", 11))
	uid := insertUserV9(t, d, "a@x.no")
	_, err := d.Exec(`INSERT INTO user_identities (id,user_id,provider,issuer,subject,email,created_at,last_used_at,admin_ok) VALUES
		(7,?,'google','https://accounts.google.com','g1','a@x.no','2026-01-01T00:00:00Z','2026-02-01T00:00:00Z',1),
		(9,?,'microsoft','https://login.microsoftonline.com/t/v2.0','m1',NULL,'2026-01-02T00:00:00Z',NULL,0)`, uid, uid)
	require.NoError(t, err)

	require.NoError(t, goose.UpTo(d, "migrations", 12))

	type row struct {
		ID, UID                            int64
		Provider, Issuer, Subject, Created string
		Email, Used                        *string
		Admin                              int
	}
	rows, err := d.Query(`SELECT id,user_id,provider,issuer,subject,email,created_at,last_used_at,admin_ok FROM user_identities ORDER BY id`)
	require.NoError(t, err)
	defer rows.Close()
	var got []row
	for rows.Next() {
		var r row
		require.NoError(t, rows.Scan(&r.ID, &r.UID, &r.Provider, &r.Issuer, &r.Subject, &r.Email, &r.Created, &r.Used, &r.Admin))
		got = append(got, r)
	}
	require.Len(t, got, 2)
	require.Equal(t, int64(7), got[0].ID)
	require.Equal(t, "google", got[0].Provider)
	require.Equal(t, 1, got[0].Admin)
	require.Equal(t, "2026-02-01T00:00:00Z", *got[0].Used)
	require.Equal(t, "2026-01-01T00:00:00Z", got[0].Created)
	require.Equal(t, int64(9), got[1].ID)
	require.Equal(t, "m1", got[1].Subject)
	require.Nil(t, got[1].Email)
	require.Equal(t, uid, got[1].UID)
	rows.Close()

	// UNIQUE(issuer, subject) og indeksen er beholdt.
	_, err = d.Exec(`INSERT INTO user_identities (user_id,provider,issuer,subject) VALUES (?,'google','https://accounts.google.com','g1')`, uid)
	require.Error(t, err)
	require.Equal(t, 1, count(t, d, `SELECT count(*) FROM sqlite_master WHERE type='index' AND name='idx_user_identities_user'`))
	// Ingen kaskade under ombyggingen.
	require.Equal(t, 1, count(t, d, `SELECT count(*) FROM users`))
}

func TestMigration012_ProviderCheck(t *testing.T) {
	d, _ := openMigrated(t)
	uid := insertUserV9(t, d, "a@x.no")
	ins := `INSERT INTO user_identities (user_id,provider,issuer,subject) VALUES (?,?,?,?)`
	_, err := d.Exec(ins, uid, "oidc", "https://idp.example", "s1")
	require.NoError(t, err)
	_, err = d.Exec(ins, uid, "x", "https://idp.example", "s2")
	require.Error(t, err)
}

func TestMigration012_Uniqueness(t *testing.T) {
	d, _ := openMigrated(t)
	addProvider(t, d, "a", 1)
	_, err := d.Exec(`INSERT INTO identity_providers (slug,display_name,issuer,client_id) VALUES ('a','A','https://other.example','c')`)
	require.Error(t, err, "duplikat slug")
	_, err = d.Exec(`INSERT INTO identity_providers (slug,display_name,issuer,client_id) VALUES ('b','B','https://a.example','c')`)
	require.Error(t, err, "duplikat issuer")
}

func TestMigration012_Cascade(t *testing.T) {
	d, _ := openMigrated(t)
	addService(t, d, "s1", 1)
	addService(t, d, "s2", 1)
	p1 := addProvider(t, d, "p1", 1)
	p2 := addProvider(t, d, "p2", 1)
	for _, c := range [][]any{{"s1", p1}, {"s1", p2}, {"s2", p1}, {"s2", p2}} {
		_, err := d.Exec(`INSERT INTO service_identity_providers (service_id,provider_id) VALUES (?,?)`, c...)
		require.NoError(t, err)
	}
	_, err := d.Exec(`DELETE FROM services WHERE id='s1'`)
	require.NoError(t, err)
	require.Equal(t, 2, count(t, d, `SELECT count(*) FROM service_identity_providers`))
	_, err = d.Exec(`DELETE FROM identity_providers WHERE id=?`, p1)
	require.NoError(t, err)
	require.Equal(t, 1, count(t, d, `SELECT count(*) FROM service_identity_providers`))
}

func TestMigration012_Down(t *testing.T) {
	t.Run("uten oidc-rader", func(t *testing.T) {
		d := openRaw(t)
		require.NoError(t, goose.UpTo(d, "migrations", 12))
		uid := insertUserV9(t, d, "a@x.no")
		_, err := d.Exec(`INSERT INTO user_identities (id,user_id,provider,issuer,subject) VALUES (5,?,'google','https://accounts.google.com','g1')`, uid)
		require.NoError(t, err)
		require.NoError(t, goose.DownTo(d, "migrations", 11))
		require.Equal(t, int64(11), gooseVersion(t, d))
		require.Equal(t, 1, count(t, d, `SELECT count(*) FROM user_identities WHERE id=5`))
		require.Equal(t, 0, count(t, d, `SELECT count(*) FROM sqlite_master WHERE name='identity_providers'`))
		_, err = d.Exec(`INSERT INTO user_identities (user_id,provider,issuer,subject) VALUES (?,'oidc','https://i','s')`, uid)
		require.Error(t, err, "gammel CHECK er tilbake")
	})
	t.Run("med oidc-rad feiler", func(t *testing.T) {
		d := openRaw(t)
		require.NoError(t, goose.UpTo(d, "migrations", 12))
		uid := insertUserV9(t, d, "a@x.no")
		_, err := d.Exec(`INSERT INTO user_identities (user_id,provider,issuer,subject) VALUES (?,'oidc','https://i','s')`, uid)
		require.NoError(t, err)
		require.Error(t, goose.DownTo(d, "migrations", 11))
		// Transaksjonen er rullet tilbake: fortsatt versjon 12 med tabellene intakte.
		require.Equal(t, int64(12), gooseVersion(t, d))
		require.Equal(t, 1, count(t, d, `SELECT count(*) FROM user_identities`))
	})
}

func TestIdentityProviderQueries(t *testing.T) {
	d, q := openMigrated(t)
	ctx := context.Background()
	addService(t, d, "s1", 1)
	addService(t, d, "s2", 1)
	addService(t, d, "off", 0)
	b := addProvider(t, d, "b", 1)
	a := addProvider(t, d, "a", 1)
	z := addProvider(t, d, "z", 1)
	dead := addProvider(t, d, "dead", 0)
	link := func(s string, p int64, pos int) {
		_, err := d.Exec(`INSERT INTO service_identity_providers (service_id,provider_id,position) VALUES (?,?,?)`, s, p, pos)
		require.NoError(t, err)
	}
	link("s1", b, 0)
	link("s1", a, 0) // lik position: slug avgjor
	link("s1", z, 1)
	link("s1", dead, 0) // inaktiv leverandor utelates
	link("s2", z, 0)
	link("off", a, 0) // inaktiv tjeneste utelates

	ps, err := q.ListActiveIdentityProviders(ctx)
	require.NoError(t, err)
	require.Len(t, ps, 3)
	require.Equal(t, []string{"a", "b", "z"}, []string{ps[0].Slug, ps[1].Slug, ps[2].Slug})
	require.Equal(t, "openid email profile", ps[0].Scopes)
	require.EqualValues(t, 0, ps[0].TrustEmail)

	ls, err := q.ListServiceIdentityProviders(ctx)
	require.NoError(t, err)
	type k struct {
		S string
		P int64
	}
	var got []k
	for _, l := range ls {
		got = append(got, k{l.ServiceID, l.ProviderID})
	}
	require.Equal(t, []k{{"s1", a}, {"s1", b}, {"s1", z}, {"s2", z}}, got)
}

func TestMigration012_ProviderChecks(t *testing.T) {
	d, _ := openMigrated(t)
	n := 0
	try := func(slug, issuer string, secret any, trust int, domains string) error {
		n++
		if slug == "" {
			slug = fmt.Sprintf("p%d", n)
		}
		if issuer == "" {
			issuer = "https://ok" + slug + ".example"
		}
		_, err := d.Exec(`INSERT INTO identity_providers (slug,display_name,issuer,client_id,client_secret_env,trust_email,email_domains) VALUES (?,?,?,?,?,?,?)`,
			slug, "N", issuer, "c", secret, trust, domains)
		return err
	}

	// a: reserverte issuere
	for _, iss := range []string{
		"https://accounts.google.com", "accounts.google.com",
		"https://login.microsoftonline.com/common/v2.0", "https://sts.windows.net/abc/",
		"https://login.live.com", "https://login.live.com/x",
	} {
		require.Error(t, try("", iss, nil, 0, ""), iss)
	}
	require.NoError(t, try("", "https://idp.example/realm", nil, 0, ""))

	// b: slug
	for _, s := range []string{"Big", "a_b", "a b", "a.b", "æ", strings32plus()} {
		require.Error(t, try(s, "", nil, 0, ""), s)
	}
	require.NoError(t, try("a-1", "", nil, 0, ""))
	require.NoError(t, try(strings32(), "", nil, 0, ""))
	_, err := d.Exec(`INSERT INTO identity_providers (slug,display_name,issuer,client_id) VALUES ('','N','https://empty.example','c')`)
	require.Error(t, err, "tom slug")

	// c: client_secret_env
	for _, e := range []string{"KAUTH_OIDC_STATE_SECRET", "KAUTH_PRIVATE_KEY_PEM", "kauth_idp_x", "KAUTH_IDP_", "KAUTH_IDP_a", "KAUTH_IDP_X-Y", "KAUTH_IDP_X Y"} {
		require.Error(t, try("", "", e, 0, ""), e)
	}
	require.NoError(t, try("", "", "KAUTH_IDP_EVAL_A", 0, ""))
	require.NoError(t, try("", "", nil, 0, ""))

	// d: trust_email krever domener
	require.Error(t, try("", "", nil, 1, ""))
	require.NoError(t, try("", "", nil, 1, "x.no"))
	require.NoError(t, try("", "", nil, 0, ""))
}

func strings32() string {
	s := ""
	for i := 0; i < 32; i++ {
		s += "a"
	}
	return s
}

func strings32plus() string { return strings32() + "a" }

func TestMigration012_OidcNeverAdmin(t *testing.T) {
	d, _ := openMigrated(t)
	uid := insertUserV9(t, d, "a@x.no")
	ins := `INSERT INTO user_identities (user_id,provider,issuer,subject,admin_ok) VALUES (?,?,?,?,?)`
	_, err := d.Exec(ins, uid, "oidc", "https://i.example", "s", 1)
	require.Error(t, err)
	_, err = d.Exec(ins, uid, "oidc", "https://i.example", "s", 0)
	require.NoError(t, err)
	_, err = d.Exec(ins, uid, "google", "https://accounts.google.com", "g", 1)
	require.NoError(t, err)
}

func TestMigration012_EmptyUserIdentities(t *testing.T) {
	d := openRaw(t)
	require.NoError(t, goose.UpTo(d, "migrations", 11))
	require.NoError(t, goose.UpTo(d, "migrations", 12))
	require.Equal(t, 0, count(t, d, `SELECT count(*) FROM user_identities`))
	uid := insertUserV9(t, d, "a@x.no")
	_, err := d.Exec(`INSERT INTO user_identities (user_id,provider,issuer,subject) VALUES (?,'oidc','https://i','s')`, uid)
	require.NoError(t, err)
}

func TestMigration012_DownKeepsAdminOkAndNullEmail(t *testing.T) {
	d := openRaw(t)
	require.NoError(t, goose.UpTo(d, "migrations", 12))
	uid := insertUserV9(t, d, "a@x.no")
	_, err := d.Exec(`INSERT INTO user_identities (id,user_id,provider,issuer,subject,email,admin_ok,last_used_at) VALUES
		(3,?,'google','https://accounts.google.com','g',NULL,1,NULL)`, uid)
	require.NoError(t, err)
	require.NoError(t, goose.DownTo(d, "migrations", 11))
	var email, used sql.NullString
	var admin int
	require.NoError(t, d.QueryRow(`SELECT email,admin_ok,last_used_at FROM user_identities WHERE id=3`).Scan(&email, &admin, &used))
	require.False(t, email.Valid)
	require.False(t, used.Valid)
	require.Equal(t, 1, admin)
}

func TestMigration012_GuardAbortsOnRowLoss(t *testing.T) {
	src, err := migrations.ReadFile("migrations/012_identity_providers.sql")
	require.NoError(t, err)
	const marker = "FROM user_identities ORDER BY id;"
	require.Contains(t, string(src), marker)
	broken := strings.Replace(string(src), marker, "FROM user_identities WHERE id <> 9 ORDER BY id;", 1)

	dir := t.TempDir()
	entries, err := migrations.ReadDir("migrations")
	require.NoError(t, err)
	for _, e := range entries {
		b, err := migrations.ReadFile("migrations/" + e.Name())
		require.NoError(t, err)
		if e.Name() == "012_identity_providers.sql" {
			b = []byte(broken)
		}
		require.NoError(t, os.WriteFile(filepath.Join(dir, e.Name()), b, 0o600))
	}

	d := openRaw(t)
	p, err := goose.NewProvider(goose.DialectSQLite3, d, os.DirFS(dir))
	require.NoError(t, err)
	ctx := context.Background()
	_, err = p.UpTo(ctx, 11)
	require.NoError(t, err)
	uid := insertUserV9(t, d, "a@x.no")
	_, err = d.Exec(`INSERT INTO user_identities (id,user_id,provider,issuer,subject) VALUES (7,?,'google','https://accounts.google.com','g1'),(9,?,'microsoft','https://m.example','m1')`, uid, uid)
	require.NoError(t, err)

	_, err = p.UpTo(ctx, 12)
	require.Error(t, err)
	require.Equal(t, 2, count(t, d, `SELECT count(*) FROM user_identities`))
	require.Equal(t, 0, count(t, d, `SELECT count(*) FROM sqlite_master WHERE name IN ('identity_providers','user_identities_new')`))
	v, err := p.GetDBVersion(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(11), v)
}

// Uten AUTOINCREMENT gjenbruker SQLite høyeste slettede id. En tilordning som
// ble liggende etter en manuell DELETE med foreign_keys av, ville da stille
// gått over til neste leverandør.
func TestMigration012_ProviderIDNeverReused(t *testing.T) {
	d, _ := openMigrated(t)
	addService(t, d, "s1", 1)
	p1 := addProvider(t, d, "p1", 1)
	_, err := d.Exec(`PRAGMA foreign_keys = OFF`)
	require.NoError(t, err)
	_, err = d.Exec(`INSERT INTO service_identity_providers (service_id,provider_id) VALUES ('s1',?)`, p1)
	require.NoError(t, err)
	_, err = d.Exec(`DELETE FROM identity_providers WHERE id=?`, p1)
	require.NoError(t, err)
	p2 := addProvider(t, d, "p2", 1)
	require.NotEqual(t, p1, p2)
	require.Zero(t, count(t, d, `SELECT count(*) FROM service_identity_providers sip JOIN identity_providers ip ON ip.id = sip.provider_id`))
}
