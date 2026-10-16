package db

import (
	"context"
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
	"github.com/zral/kauth-go/internal/db/gen"
)

const (
	t0      = "2026-03-01T12:00:00Z"
	tFuture = "2026-03-01T12:30:00Z"
	tNow    = "2026-03-01T12:10:00Z"
	tAfter  = "2026-03-01T12:40:00Z"
)

func newInvite(hash string, uid, pid int64, svc string) gen.InsertLinkInviteLimitedParams {
	return gen.InsertLinkInviteLimitedParams{
		TokenHash: hash, UserID: uid, ProviderID: pid, ServiceID: svc, Email: "a@x.no",
		CreatedBy: "admin@x.no", CreatedAt: t0, ExpiresAt: tFuture, WindowStart: "2026-03-01T11:00:00Z",
	}
}

func TestMigration013_UpDownWithData(t *testing.T) {
	d := openRaw(t)
	require.NoError(t, goose.UpTo(d, "migrations", 12))
	uid := insertUserV9(t, d, "a@x.no")
	addService(t, d, "s1", 1)
	p := addProvider(t, d, "p1", 1)
	_, err := d.Exec(`INSERT INTO user_identities (user_id,provider,issuer,subject) VALUES (?,'oidc','https://i','s')`, uid)
	require.NoError(t, err)

	require.NoError(t, goose.UpTo(d, "migrations", 13))
	require.Equal(t, 1, count(t, d, `SELECT count(*) FROM sqlite_master WHERE name='identity_link_invites'`))
	require.True(t, hasIndex(t, d, "idx_link_invites_user"))
	// Eksisterende data er urørt.
	require.Equal(t, 1, count(t, d, `SELECT count(*) FROM user_identities`))
	require.Equal(t, 1, count(t, d, `SELECT count(*) FROM users`))
	_, err = d.Exec(`INSERT INTO identity_link_invites (token_hash,user_id,provider_id,service_id,email,created_by,created_at,expires_at) VALUES ('h',?,?,'s1','a@x.no','adm',?,?)`, uid, p, t0, tFuture)
	require.NoError(t, err)
	_, err = d.Exec(`INSERT INTO identity_link_invites (token_hash,user_id,provider_id,service_id,email,created_by,created_at,expires_at) VALUES ('h',?,?,'s1','a@x.no','adm',?,?)`, uid, p, t0, tFuture)
	require.Error(t, err, "token_hash er UNIQUE")

	require.NoError(t, goose.DownTo(d, "migrations", 12))
	require.Equal(t, int64(12), gooseVersion(t, d))
	require.Equal(t, 0, count(t, d, `SELECT count(*) FROM sqlite_master WHERE name='identity_link_invites'`))
	require.Equal(t, 1, count(t, d, `SELECT count(*) FROM user_identities`))
	require.Equal(t, 1, count(t, d, `SELECT count(*) FROM identity_providers`))
}

func TestMigration013_Cascade(t *testing.T) {
	for _, tc := range []struct{ name, del string }{
		{"bruker", `DELETE FROM users WHERE id=?`},
		{"leverandor", `DELETE FROM identity_providers WHERE id=?`},
		{"tjeneste", `DELETE FROM services WHERE id='s1'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, q := openMigrated(t)
			uid := insertUserV9(t, d, "a@x.no")
			addService(t, d, "s1", 1)
			p := addProvider(t, d, "p1", 1)
			n, err := q.InsertLinkInviteLimited(context.Background(), newInvite("h", uid, p, "s1"))
			require.NoError(t, err)
			require.EqualValues(t, 1, n)
			arg := uid
			if tc.name == "leverandor" {
				arg = p
			}
			if tc.name == "tjeneste" {
				_, err = d.Exec(tc.del)
			} else {
				_, err = d.Exec(tc.del, arg)
			}
			require.NoError(t, err)
			require.Zero(t, count(t, d, `SELECT count(*) FROM identity_link_invites`))
		})
	}
}

func TestInsertLinkInviteLimited(t *testing.T) {
	d, q := openMigrated(t)
	ctx := context.Background()
	u1 := insertUserV9(t, d, "a@x.no")
	u2 := insertUserV9(t, d, "b@x.no")
	addService(t, d, "s1", 1)
	p := addProvider(t, d, "p1", 1)

	for i := 0; i < 5; i++ {
		n, err := q.InsertLinkInviteLimited(ctx, newInvite("h"+string(rune('a'+i)), u1, p, "s1"))
		require.NoError(t, err)
		require.EqualValues(t, 1, n, i)
	}
	n, err := q.InsertLinkInviteLimited(ctx, newInvite("h6", u1, p, "s1"))
	require.NoError(t, err)
	require.EqualValues(t, 0, n, "6. innenfor en time stoppes")

	// Brente invitasjoner teller fortsatt.
	_, err = q.BurnLinkInvitesForUser(ctx, gen.BurnLinkInvitesForUserParams{Now: tNow, UserID: u1})
	require.NoError(t, err)
	n, err = q.InsertLinkInviteLimited(ctx, newInvite("h7", u1, p, "s1"))
	require.NoError(t, err)
	require.EqualValues(t, 0, n)

	// Annen bruker påvirkes ikke.
	n, err = q.InsertLinkInviteLimited(ctx, newInvite("h8", u2, p, "s1"))
	require.NoError(t, err)
	require.EqualValues(t, 1, n)

	// Utenfor vinduet telles ikke.
	late := newInvite("h9", u1, p, "s1")
	late.WindowStart = "2026-03-01T12:01:00Z"
	n, err = q.InsertLinkInviteLimited(ctx, late)
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
}

func TestConsumeLinkInvite(t *testing.T) {
	d, q := openMigrated(t)
	ctx := context.Background()
	u := insertUserV9(t, d, "a@x.no")
	addService(t, d, "s1", 1)
	p := addProvider(t, d, "p1", 1)
	other := addProvider(t, d, "p2", 1)
	_, err := q.InsertLinkInviteLimited(ctx, newInvite("h", u, p, "s1"))
	require.NoError(t, err)
	inv, err := q.GetValidLinkInviteByHash(ctx, gen.GetValidLinkInviteByHashParams{TokenHash: "h", Now: tNow})
	require.NoError(t, err)
	require.Equal(t, "a@x.no", inv.Email)
	require.Equal(t, "s1", inv.ServiceID)
	require.Nil(t, inv.UsedAt)

	// Feil leverandør, og utløpt: ingen forbruk.
	_, err = q.ConsumeLinkInvite(ctx, gen.ConsumeLinkInviteParams{Now: tNow, ID: inv.ID, ProviderID: other, ServiceID: "s1"})
	require.ErrorIs(t, err, sql.ErrNoRows)
	_, err = q.ConsumeLinkInvite(ctx, gen.ConsumeLinkInviteParams{Now: tAfter, ID: inv.ID, ProviderID: p, ServiceID: "s1"})
	require.ErrorIs(t, err, sql.ErrNoRows)
	_, err = q.GetValidLinkInviteByHash(ctx, gen.GetValidLinkInviteByHashParams{TokenHash: "h", Now: tAfter})
	require.ErrorIs(t, err, sql.ErrNoRows)

	_, err = q.ConsumeLinkInvite(ctx, gen.ConsumeLinkInviteParams{Now: tNow, ID: inv.ID, ProviderID: p, ServiceID: "annen"})
	require.ErrorIs(t, err, sql.ErrNoRows, "feil tjeneste")
	still, err := q.GetValidLinkInviteByHash(ctx, gen.GetValidLinkInviteByHashParams{TokenHash: "h", Now: tNow})
	require.NoError(t, err)
	require.Nil(t, still.UsedAt, "fortsatt ubrukt")

	// Grense: expires_at == now er ikke gyldig.
	_, err = q.ConsumeLinkInvite(ctx, gen.ConsumeLinkInviteParams{Now: tFuture, ID: inv.ID, ProviderID: p, ServiceID: "s1"})
	require.ErrorIs(t, err, sql.ErrNoRows)
	_, err = q.GetValidLinkInviteByHash(ctx, gen.GetValidLinkInviteByHashParams{TokenHash: "h", Now: tFuture})
	require.ErrorIs(t, err, sql.ErrNoRows)

	got, err := q.ConsumeLinkInvite(ctx, gen.ConsumeLinkInviteParams{Now: tNow, ID: inv.ID, ProviderID: p, ServiceID: "s1"})
	require.NoError(t, err)
	require.Equal(t, inv.ID, got.ID)
	require.NotNil(t, got.UsedAt)
	require.Equal(t, tNow, *got.UsedAt)

	_, err = q.ConsumeLinkInvite(ctx, gen.ConsumeLinkInviteParams{Now: tNow, ID: inv.ID, ProviderID: p, ServiceID: "s1"})
	require.ErrorIs(t, err, sql.ErrNoRows, "kun én gang")
	_, err = q.GetValidLinkInviteByHash(ctx, gen.GetValidLinkInviteByHashParams{TokenHash: "h", Now: tNow})
	require.ErrorIs(t, err, sql.ErrNoRows)
	byID, err := q.GetLinkInviteByID(ctx, inv.ID)
	require.NoError(t, err)
	require.NotNil(t, byID.UsedAt)
}

func TestRevokeLinkInvite(t *testing.T) {
	d, q := openMigrated(t)
	ctx := context.Background()
	u := insertUserV9(t, d, "a@x.no")
	v := insertUserV9(t, d, "b@x.no")
	addService(t, d, "s1", 1)
	p := addProvider(t, d, "p1", 1)
	_, err := q.InsertLinkInviteLimited(ctx, newInvite("h", u, p, "s1"))
	require.NoError(t, err)
	inv, err := q.GetValidLinkInviteByHash(ctx, gen.GetValidLinkInviteByHashParams{TokenHash: "h", Now: tNow})
	require.NoError(t, err)

	n, err := q.RevokeLinkInvite(ctx, gen.RevokeLinkInviteParams{Now: tNow, ID: inv.ID, UserID: v})
	require.NoError(t, err)
	require.EqualValues(t, 0, n, "feil user_id")
	act, err := q.ListActiveLinkInvitesByUser(ctx, gen.ListActiveLinkInvitesByUserParams{UserID: u, Now: tNow})
	require.NoError(t, err)
	require.Len(t, act, 1)

	n, err = q.RevokeLinkInvite(ctx, gen.RevokeLinkInviteParams{Now: tNow, ID: inv.ID, UserID: u})
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	n, err = q.RevokeLinkInvite(ctx, gen.RevokeLinkInviteParams{Now: tNow, ID: inv.ID, UserID: u})
	require.NoError(t, err)
	require.EqualValues(t, 0, n, "allerede brukt")
	act, err = q.ListActiveLinkInvitesByUser(ctx, gen.ListActiveLinkInvitesByUserParams{UserID: u, Now: tNow})
	require.NoError(t, err)
	require.Empty(t, act)
	_, err = q.GetValidLinkInviteByHash(ctx, gen.GetValidLinkInviteByHashParams{TokenHash: "h", Now: tNow})
	require.ErrorIs(t, err, sql.ErrNoRows)
}

func TestBurnLinkInvites_ScopedToUserAndProvider(t *testing.T) {
	d, q := openMigrated(t)
	ctx := context.Background()
	u := insertUserV9(t, d, "a@x.no")
	v := insertUserV9(t, d, "b@x.no")
	addService(t, d, "s1", 1)
	p1 := addProvider(t, d, "p1", 1)
	p2 := addProvider(t, d, "p2", 1)
	for _, c := range []struct {
		h string
		u int64
		p int64
	}{{"uA", u, p1}, {"uB", u, p2}, {"vA", v, p1}} {
		_, err := q.InsertLinkInviteLimited(ctx, newInvite(c.h, c.u, c.p, "s1"))
		require.NoError(t, err)
	}
	n, err := q.BurnLinkInvites(ctx, gen.BurnLinkInvitesParams{Now: tNow, UserID: u, ProviderID: p1})
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	require.Equal(t, 2, count(t, d, `SELECT count(*) FROM identity_link_invites WHERE used_at IS NULL`))
	require.Equal(t, 1, count(t, d, `SELECT count(*) FROM identity_link_invites WHERE used_at IS NOT NULL AND token_hash='uA'`))

	n, err = q.BurnLinkInvitesForUser(ctx, gen.BurnLinkInvitesForUserParams{Now: tNow, UserID: u})
	require.NoError(t, err)
	require.EqualValues(t, 1, n, "bare uB gjenstår for u")
	require.Equal(t, 1, count(t, d, `SELECT count(*) FROM identity_link_invites WHERE used_at IS NULL AND token_hash='vA'`))
}

func TestDeleteExpiredLinkInvites(t *testing.T) {
	d, q := openMigrated(t)
	ctx := context.Background()
	u := insertUserV9(t, d, "a@x.no")
	addService(t, d, "s1", 1)
	p := addProvider(t, d, "p1", 1)
	_, err := q.InsertLinkInviteLimited(ctx, newInvite("h", u, p, "s1"))
	require.NoError(t, err)
	require.NoError(t, q.DeleteExpiredLinkInvites(ctx, tNow))
	require.Equal(t, 1, count(t, d, `SELECT count(*) FROM identity_link_invites`))
	require.NoError(t, q.DeleteExpiredLinkInvites(ctx, tAfter))
	require.Zero(t, count(t, d, `SELECT count(*) FROM identity_link_invites`))
}

func TestProviderAdminQueries(t *testing.T) {
	d, q := openMigrated(t)
	ctx := context.Background()
	addService(t, d, "s1", 1)
	addService(t, d, "s2", 0)
	b := addProvider(t, d, "b", 1)
	a := addProvider(t, d, "a", 0)

	all, err := q.ListAllIdentityProviders(ctx)
	require.NoError(t, err)
	require.Len(t, all, 2, "også inaktive")
	require.Equal(t, "a", all[0].Slug)

	names, err := q.ListIdentityProviderNames(ctx)
	require.NoError(t, err)
	require.Len(t, names, 2)

	for _, c := range []gen.InsertServiceIdentityProviderParams{
		{ServiceID: "s1", ProviderID: b, Position: 1}, {ServiceID: "s1", ProviderID: a, Position: 0}, {ServiceID: "s2", ProviderID: a, Position: 0},
	} {
		require.NoError(t, q.InsertServiceIdentityProvider(ctx, c))
	}
	allA, err := q.ListServiceIdentityProvidersAll(ctx)
	require.NoError(t, err)
	require.Len(t, allA, 3, "uavhengig av active")
	forS1, err := q.ListAssignmentsForService(ctx, "s1")
	require.NoError(t, err)
	require.Len(t, forS1, 2)
	require.Equal(t, "a", forS1[0].Slug)
	require.Equal(t, "b", forS1[1].Slug)

	require.NoError(t, q.DeleteServiceIdentityProviders(ctx, "s1"))
	forS1, err = q.ListAssignmentsForService(ctx, "s1")
	require.NoError(t, err)
	require.Empty(t, forS1)
	forS2, err := q.ListAssignmentsForService(ctx, "s2")
	require.NoError(t, err)
	require.Len(t, forS2, 1)
}
