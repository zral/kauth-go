package idp

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zral/kauth-go/internal/db/gen"
)

func TestStatus_PerReason(t *testing.T) {
	const iss = "https://idp.acme.example"
	cases := []struct {
		name   string
		mod    func(*gen.IdentityProvider)
		opts   Options
		reason string
	}{
		{"lastet", func(r *gen.IdentityProvider) {}, optsFor(iss), ""},
		{"inaktiv", func(r *gen.IdentityProvider) { r.Active = 0 }, optsFor(iss), "inactive"},
		{"slug", func(r *gen.IdentityProvider) { r.Slug = "Bad Slug" }, optsFor(iss), "bad_slug"},
		{"navn tomt", func(r *gen.IdentityProvider) { r.DisplayName = " " }, optsFor(iss), "display_name_empty"},
		{"ikke allowlistet", func(r *gen.IdentityProvider) {}, optsFor(), "issuer_not_allowlisted"},
		{"reservert", func(r *gen.IdentityProvider) { r.Issuer = "https://accounts.google.com" }, optsFor("https://accounts.google.com"), "issuer_reserved"},
		{"env-navn", func(r *gen.IdentityProvider) { r.ClientSecretEnv = strp("PATH") }, optsFor(iss), "secret_env_name"},
		{"env tom", func(r *gen.IdentityProvider) { r.ClientSecretEnv = strp("KAUTH_IDP_NONE") }, optsFor(iss), "secret_env_empty"},
		{"scope", func(r *gen.IdentityProvider) { r.Scopes = "email" }, optsFor(iss), "scope_openid_missing"},
		{"domene", func(r *gen.IdentityProvider) { r.EmailDomains = "a@b" }, optsFor(iss), "bad_email_domain"},
		{"trust uten domener", func(r *gen.IdentityProvider) { r.TrustEmail = 1 }, optsFor(iss), "trust_email_without_domains"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			row := goodRow()
			c.mod(&row)
			_, reason, ok := validate(row, c.opts)
			st := buildStatus(row, c.opts, ok, reason)
			require.Equal(t, c.reason, st.Reason)
			require.Equal(t, c.reason == "", st.Loaded)
			require.Equal(t, row.Active == 1, st.Active)
			require.Equal(t, row.Slug, st.Slug)
			require.Equal(t, inAllowlist(c.opts.Allowlist, row.Issuer), st.Allowlisted)
		})
	}
}

func TestStatus_SecretSetAndNoLeak(t *testing.T) {
	row := goodRow()
	o := optsFor(row.Issuer)
	st := buildStatus(row, o, true, "")
	require.True(t, st.SecretSet)
	require.Equal(t, "KAUTH_IDP_ACME", st.SecretEnv)
	for _, s := range []string{fmt.Sprintf("%+v", st), fmt.Sprintf("%#v", st), fmt.Sprint(st)} {
		require.NotContains(t, s, "s3cret")
	}
	unset := buildStatus(row, Options{Getenv: func(string) string { return "" }}, false, "secret_env_empty")
	require.False(t, unset.SecretSet)
	pub := row
	pub.ClientSecretEnv = nil
	require.False(t, buildStatus(pub, o, true, "").SecretSet)
}

func TestLoad_StatusesIncludeInactive(t *testing.T) {
	q, ex := setup(t)
	ex(`INSERT INTO identity_providers (id,slug,display_name,issuer,client_id,active) VALUES
		(1,'a','A','https://a.example','c',1),(2,'b','B','https://b.example','c',0),(3,'c','C','https://c.example','c',1)`)
	_, _, st, err := Load(context.Background(), q, Options{Allowlist: []string{"https://a.example", "https://b.example"}})
	require.NoError(t, err)
	require.Len(t, st, 3)
	require.True(t, st[0].Loaded)
	require.Equal(t, "inactive", st[1].Reason)
	require.True(t, st[1].Allowlisted)
	require.Equal(t, "issuer_not_allowlisted", st[2].Reason)
}

// reloadSetup lager 3 lastede leverandører (id 1-3) og en ikke-lastet (id 4).
func reloadSetup(t *testing.T) (*Registry, *gen.Queries, func(string, ...any)) {
	q, ex := setup(t)
	ex(`INSERT INTO identity_providers (id,slug,display_name,issuer,client_id) VALUES
		(1,'a','A','https://a.example','c'),(2,'b','B','https://b.example','c'),(3,'c','C','https://c.example','c'),(4,'x','X','https://x.example','c')`)
	ex(`INSERT INTO services (id,display_name,domain,callback_url,email_from_name,updated_at,active) VALUES ('s','s','s.no','https://s.no/cb','S','2026-01-01T00:00:00Z',1)`)
	ex(`INSERT INTO service_identity_providers (service_id,provider_id,position) VALUES ('s',1,0)`)
	provs := map[string]Provider{}
	for i, s := range []string{"a", "b", "c"} {
		provs[s] = Provider{ID: int64(i + 1), Slug: s}
	}
	return NewRegistry(provs, map[string][]string{"s": {"a"}}, NewHTTPClient(true), true), q, ex
}

func slugs(ps []Provider) []string {
	out := []string{}
	for _, p := range ps {
		out = append(out, p.Slug)
	}
	return out
}

func TestReloadAssignments(t *testing.T) {
	r, q, ex := reloadSetup(t)
	ctx := context.Background()
	steps := []struct {
		name string
		sql  string
		want []string
	}{
		{"legger til", `INSERT INTO service_identity_providers VALUES ('s',2,1)`, []string{"a", "b"}},
		{"endrer rekkefølge", `UPDATE service_identity_providers SET position = CASE provider_id WHEN 1 THEN 5 ELSE 0 END`, []string{"b", "a"}},
		{"ignorerer ikke-lastet", `INSERT INTO service_identity_providers VALUES ('s',4,0)`, []string{"b", "a"}},
		{"fjerner", `DELETE FROM service_identity_providers WHERE provider_id IN (1,2)`, []string{}},
	}
	for _, s := range steps {
		ex(s.sql)
		require.NoError(t, r.ReloadAssignments(ctx, q), s.name)
		require.Equal(t, s.want, slugs(r.ForService("s")), s.name)
	}
}

func TestReloadAssignments_ErrorKeepsOld(t *testing.T) {
	r, q, ex := reloadSetup(t)
	ex(`DROP TABLE service_identity_providers`)
	require.Error(t, r.ReloadAssignments(context.Background(), q))
	require.Equal(t, []string{"a"}, slugs(r.ForService("s")))
}

func TestForService_ReturnsCopy(t *testing.T) {
	r, _, _ := reloadSetup(t)
	got := r.ForService("s")
	got[0].Slug = "mutert"
	require.Equal(t, "a", r.ForService("s")[0].Slug)
	require.Equal(t, "a", r.providers["a"].Slug)
}

func TestStatuses_ReturnsCopy(t *testing.T) {
	in := []Status{{Slug: "a", EmailDomains: []string{"x.no"}}}
	r := NewRegistryWithStatuses(nil, nil, in, NewHTTPClient(true), true)
	got := r.Statuses()
	got[0].Slug = "mutert"
	got[0].EmailDomains[0] = "mutert"
	again := r.Statuses()
	require.Equal(t, "a", again[0].Slug)
	require.Equal(t, []string{"x.no"}, again[0].EmailDomains)
}

func TestForService_ConcurrentReload(t *testing.T) {
	r, q, ex := reloadSetup(t)
	ex(`INSERT INTO service_identity_providers VALUES ('s',2,1)`)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				for _, p := range r.ForService("s") {
					_ = p.Slug
				}
			}
		}()
	}
	for i := 0; i < 20; i++ {
		require.NoError(t, r.ReloadAssignments(context.Background(), q))
	}
	wg.Wait()
}

func TestReloadAssignments_ByServiceExcludesUnloaded(t *testing.T) {
	r, q, ex := reloadSetup(t)
	ex(`INSERT INTO service_identity_providers VALUES ('s',4,1)`)
	require.NoError(t, r.ReloadAssignments(context.Background(), q))
	r.assignMu.RLock()
	defer r.assignMu.RUnlock()
	require.Equal(t, []string{"a"}, r.byService["s"])
}
