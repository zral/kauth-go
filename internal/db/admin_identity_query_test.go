package db_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

func mkUser(t *testing.T, q *gen.Queries, email string) gen.User {
	t.Helper()
	u, err := q.CreateUser(context.Background(), gen.CreateUserParams{
		PublicID: token.MustNewPublicID(), Email: email, Roles: "user", Orgs: "o", CreatedAt: "2026-01-01T00:00:00Z",
	})
	require.NoError(t, err)
	return u
}

func TestUpdateUserEmail_Conditional(t *testing.T) {
	ctx := context.Background()
	_, q := openTestDB(t)
	a := mkUser(t, q, "a@x.no")
	mkUser(t, q, "taken@x.no")
	at := "2026-10-15T10:00:00Z"

	n, err := q.UpdateUserEmail(ctx, gen.UpdateUserEmailParams{NewEmail: "new@x.no", EmailChangedAt: &at, ID: a.ID, OldEmail: "feil@x.no"})
	require.NoError(t, err)
	assert.EqualValues(t, 0, n, "feil gammel e-post gir 0 rader")

	for _, taken := range []string{"taken@x.no", "Taken@X.no"} {
		_, err = q.UpdateUserEmail(ctx, gen.UpdateUserEmailParams{NewEmail: taken, EmailChangedAt: &at, ID: a.ID, OldEmail: "a@x.no"})
		require.Error(t, err, taken)
		assert.True(t, strings.Contains(err.Error(), "UNIQUE"), "unik-brudd (også med annen case via idx_users_email_norm): %v", err)
	}
	got, err := q.GetUserByID(ctx, a.ID)
	require.NoError(t, err)
	assert.Equal(t, "a@x.no", got.Email)
	assert.Nil(t, got.EmailChangedAt)

	n, err = q.UpdateUserEmail(ctx, gen.UpdateUserEmailParams{NewEmail: "new@x.no", EmailChangedAt: &at, ID: a.ID, OldEmail: "a@x.no"})
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
	got, err = q.GetUserByID(ctx, a.ID)
	require.NoError(t, err)
	assert.Equal(t, "new@x.no", got.Email)
	require.NotNil(t, got.EmailChangedAt)
	assert.Equal(t, at, *got.EmailChangedAt)
}

func TestBindAdmin_OnlyOnce(t *testing.T) {
	ctx := context.Background()
	_, q := openTestDB(t)
	u := mkUser(t, q, "a@x.no")
	first, second := "2026-10-15T10:00:00Z", "2026-10-16T10:00:00Z"

	n, err := q.BindAdmin(ctx, gen.BindAdminParams{AdminBoundAt: &first, ID: u.ID})
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
	n, err = q.BindAdmin(ctx, gen.BindAdminParams{AdminBoundAt: &second, ID: u.ID})
	require.NoError(t, err)
	assert.EqualValues(t, 0, n, "andre kall treffer ingen rad")

	got, err := q.GetUserByID(ctx, u.ID)
	require.NoError(t, err)
	require.NotNil(t, got.AdminBoundAt)
	assert.Equal(t, first, *got.AdminBoundAt)
}

func TestDeleteIdentity_RequiresOwner(t *testing.T) {
	ctx := context.Background()
	sqldb, q := openTestDB(t)
	a, b := mkUser(t, q, "a@x.no"), mkUser(t, q, "b@x.no")
	_, err := q.InsertIdentity(ctx, gen.InsertIdentityParams{UserID: a.ID, Provider: "google", Issuer: "https://accounts.google.com", Subject: "s1", CreatedAt: "2026-01-01T00:00:00Z"})
	require.NoError(t, err)
	idn, err := q.GetIdentity(ctx, gen.GetIdentityParams{Issuer: "https://accounts.google.com", Subject: "s1"})
	require.NoError(t, err)
	_, err = sqldb.Exec(`UPDATE user_identities SET admin_ok = 1 WHERE id = ?`, idn.ID)
	require.NoError(t, err)

	_, err = q.DeleteIdentity(ctx, gen.DeleteIdentityParams{ID: idn.ID, UserID: b.ID})
	require.ErrorIs(t, err, sql.ErrNoRows)
	var n int
	require.NoError(t, sqldb.QueryRow(`SELECT count(*) FROM user_identities WHERE id = ?`, idn.ID).Scan(&n))
	assert.Equal(t, 1, n, "raden står")

	row, err := q.DeleteIdentity(ctx, gen.DeleteIdentityParams{ID: idn.ID, UserID: a.ID})
	require.NoError(t, err)
	assert.Equal(t, gen.DeleteIdentityRow{Provider: "google", Issuer: "https://accounts.google.com", AdminOk: 1}, row)
	require.NoError(t, sqldb.QueryRow(`SELECT count(*) FROM user_identities WHERE id = ?`, idn.ID).Scan(&n))
	assert.Equal(t, 0, n)
}

func TestSetAdminOK_RequiresOwner(t *testing.T) {
	ctx := context.Background()
	sqldb, q := openTestDB(t)
	a, b := mkUser(t, q, "a@x.no"), mkUser(t, q, "b@x.no")
	_, err := q.InsertIdentity(ctx, gen.InsertIdentityParams{UserID: a.ID, Provider: "google", Issuer: "https://accounts.google.com", Subject: "s1", CreatedAt: "2026-01-01T00:00:00Z"})
	require.NoError(t, err)
	idn, err := q.GetIdentity(ctx, gen.GetIdentityParams{Issuer: "https://accounts.google.com", Subject: "s1"})
	require.NoError(t, err)

	bound := "2026-10-15T10:00:00Z"
	nb, err := q.BindAdmin(ctx, gen.BindAdminParams{AdminBoundAt: &bound, ID: a.ID})
	require.NoError(t, err)
	require.EqualValues(t, 1, nb)
	nb, err = q.BindAdmin(ctx, gen.BindAdminParams{AdminBoundAt: &bound, ID: b.ID})
	require.NoError(t, err)
	require.EqualValues(t, 1, nb)

	// Identiteten tilhorer a, ikke b.
	n, err := q.SetAdminOK(ctx, gen.SetAdminOKParams{ID: idn.ID, UserID: b.ID, BoundAt: &bound})
	require.NoError(t, err)
	assert.EqualValues(t, 0, n)
	n, err = q.SetAdminOK(ctx, gen.SetAdminOKParams{ID: idn.ID, UserID: a.ID, BoundAt: &bound})
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)
	var ok int
	require.NoError(t, sqldb.QueryRow(`SELECT admin_ok FROM user_identities WHERE id = ?`, idn.ID).Scan(&ok))
	assert.Equal(t, 1, ok)
}

// S1: SetAdminOK er selvhandhevende. Uten en binding som skrev noyaktig dette
// tidsstempelet kan admin_ok ikke settes, selv for riktig eier.
func TestSetAdminOK_RequiresMatchingBinding(t *testing.T) {
	ctx := context.Background()
	sqldb, q := openTestDB(t)
	a := mkUser(t, q, "a@x.no")
	_, err := q.InsertIdentity(ctx, gen.InsertIdentityParams{UserID: a.ID, Provider: "google", Issuer: "https://accounts.google.com", Subject: "s1", CreatedAt: "2026-01-01T00:00:00Z"})
	require.NoError(t, err)
	idn, err := q.GetIdentity(ctx, gen.GetIdentityParams{Issuer: "https://accounts.google.com", Subject: "s1"})
	require.NoError(t, err)
	mine, other := "2026-10-15T10:00:00Z", "2026-10-15T10:00:01Z"

	// Ubundet bruker.
	n, err := q.SetAdminOK(ctx, gen.SetAdminOKParams{ID: idn.ID, UserID: a.ID, BoundAt: &mine})
	require.NoError(t, err)
	assert.EqualValues(t, 0, n)

	// Bundet med et annet tidsstempel (en annen innlogging vant).
	nb, err := q.BindAdmin(ctx, gen.BindAdminParams{AdminBoundAt: &other, ID: a.ID})
	require.NoError(t, err)
	require.EqualValues(t, 1, nb)
	n, err = q.SetAdminOK(ctx, gen.SetAdminOKParams{ID: idn.ID, UserID: a.ID, BoundAt: &mine})
	require.NoError(t, err)
	assert.EqualValues(t, 0, n)

	var ok int
	require.NoError(t, sqldb.QueryRow(`SELECT admin_ok FROM user_identities WHERE id = ?`, idn.ID).Scan(&ok))
	assert.Equal(t, 0, ok)
}

func TestBurnMagicTokens_KeepsQuotaRows(t *testing.T) {
	ctx := context.Background()
	sqldb, q := openTestDB(t)
	ins := func(tok, email string) {
		n, err := q.InsertMagicTokenLimited(ctx, gen.InsertMagicTokenLimitedParams{
			TokenHash: tok, Email: email, Purpose: "service",
			CreatedAt: "2026-10-15T10:00:00Z", ExpiresAt: "2099-01-01T00:00:00Z", WindowStart: "2026-10-15T09:45:00Z",
		})
		require.NoError(t, err)
		require.EqualValues(t, 1, n)
	}
	ins("t-old", "old@x.no")
	ins("t-new", "new@x.no")
	ins("t-other", "other@x.no")
	_, err := sqldb.Exec(`INSERT INTO magic_tokens (token,email,purpose,created_at,expires_at) VALUES ('t-expired','old@x.no','service','2026-01-01T00:00:00Z','2026-01-01T00:15:00Z')`)
	require.NoError(t, err)

	var before int
	require.NoError(t, sqldb.QueryRow(`SELECT count(*) FROM magic_tokens`).Scan(&before))

	n, err := q.BurnMagicTokensForEmails(ctx, gen.BurnMagicTokensForEmailsParams{OldEmail: "old@x.no", NewEmail: "new@x.no", Now: "2026-10-15T10:05:00Z"})
	require.NoError(t, err)
	assert.EqualValues(t, 2, n, "utløpt token telles ikke")

	used := func(tok string) int {
		var u int
		require.NoError(t, sqldb.QueryRow(`SELECT used FROM magic_tokens WHERE token = ?`, tok).Scan(&u))
		return u
	}
	assert.Equal(t, 1, used("t-old"))
	assert.Equal(t, 1, used("t-new"))
	assert.Equal(t, 0, used("t-other"), "tredje adresse er urørt")
	var after int
	require.NoError(t, sqldb.QueryRow(`SELECT count(*) FROM magic_tokens`).Scan(&after))
	assert.Equal(t, before, after, "kvoteradene står")
}
