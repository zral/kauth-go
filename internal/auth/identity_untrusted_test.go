package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/db/gen"
)

// Uten e-posttillit gjelder bare en allerede kjent identitet (PD7).
func TestResolve_EmailUntrusted(t *testing.T) {
	ctx := context.Background()
	untrusted := linkPolicy{AutoLink: true, AutoRegister: true, EmailUntrusted: true}

	t.Run("kjent identitet gir bruker selv uten tillit", func(t *testing.T) {
		f := newResolveFx(t)
		a := f.user(t, "a@x.no")
		f.identity(t, a.ID, "s1")
		u, out, err := f.r.resolve(ctx, gext("s1", "annen@x.no"), untrusted, resolveMeta{})
		require.NoError(t, err)
		require.Equal(t, a.ID, u.ID)
		require.Equal(t, outcomeMatched, out)
	})
	t.Run("kjent identitet med tom e-post", func(t *testing.T) {
		f := newResolveFx(t)
		a := f.user(t, "a@x.no")
		f.identity(t, a.ID, "s1")
		u, _, err := f.r.resolve(ctx, gext("s1", ""), untrusted, resolveMeta{})
		require.NoError(t, err)
		require.Equal(t, a.ID, u.ID)
	})
	t.Run("ukjent identitet med eksisterende e-post kobles ikke", func(t *testing.T) {
		f := newResolveFx(t)
		f.user(t, "a@x.no")
		_, _, err := f.r.resolve(ctx, gext("ny", "a@x.no"), untrusted, resolveMeta{})
		require.ErrorIs(t, err, errNoAccount)
		var n int
		require.NoError(t, f.db.QueryRow(`SELECT COUNT(*) FROM user_identities`).Scan(&n))
		require.Zero(t, n)
	})
	t.Run("ukjent identitet registreres ikke", func(t *testing.T) {
		f := newResolveFx(t)
		_, _, err := f.r.resolve(ctx, gext("ny", "ny@x.no"), untrusted, resolveMeta{})
		require.ErrorIs(t, err, errNoAccount)
		var n int
		require.NoError(t, f.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n))
		require.Zero(t, n)
	})
	t.Run("med tillit som før", func(t *testing.T) {
		f := newResolveFx(t)
		f.user(t, "a@x.no")
		_, out, err := f.r.resolve(ctx, gext("ny", "a@x.no"), linkPolicy{AutoLink: true, AutoRegister: true}, resolveMeta{})
		require.NoError(t, err)
		require.Equal(t, outcomeLinked, out)
	})
}

// Google og Microsoft er uendret: policyFor gir tillit, så nullverdien gjelder.
func TestPolicyFor_EmailTrustedByDefault(t *testing.T) {
	require.False(t, policyFor(&gen.Service{AutoLink: 1, AutoRegister: 1}).EmailUntrusted)
}
