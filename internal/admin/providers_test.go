package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/fetchmeta"
	"github.com/zral/kauth-go/internal/idp"
	"github.com/zral/kauth-go/internal/token"
)

const knownSecret = "hemmelig-verdi-4711"

// provEnv har leverandører i alle tilstander: acme (lastet), skjult (avvist, ikke i
// allowlist), av (inaktiv) og et lastet navn med HTML i.
type provEnv struct {
	*f3Env
	idps *idp.Registry
	mux  http.Handler
	svcs *ServicesHandler
}

func newProvEnv(t *testing.T) *provEnv {
	t.Helper()
	f := newF3Env(t)
	ctx := context.Background()
	for _, q := range []string{
		`INSERT INTO identity_providers (id,slug,display_name,issuer,client_id,client_secret_env) VALUES (1,'acme','Acme','https://idp.acme.example','c1','KAUTH_IDP_ACME')`,
		`INSERT INTO identity_providers (id,slug,display_name,issuer,client_id) VALUES (2,'skjult','Skjult','https://skjult.example','c2')`,
		`INSERT INTO identity_providers (id,slug,display_name,issuer,client_id,active) VALUES (3,'av','Av','https://av.example','c3',0)`,
		`INSERT INTO identity_providers (id,slug,display_name,issuer,client_id) VALUES (4,'xss','<b>Fet</b> & co','https://xss.example','c4')`,
		`INSERT INTO service_identity_providers (service_id,provider_id,position) VALUES ('svca',1,2)`,
		`INSERT INTO service_identity_providers (service_id,provider_id,position) VALUES ('svca',2,5)`,
	} {
		_, err := f.sqldb.Exec(q)
		require.NoError(t, err, q)
	}
	opts := idp.Options{
		Allowlist: []string{"https://idp.acme.example", "https://av.example", "https://xss.example"},
		Getenv: func(k string) string {
			if k == "KAUTH_IDP_ACME" {
				return knownSecret
			}
			return ""
		},
	}
	provs, by, sts, err := idp.Load(ctx, f.q, opts)
	require.NoError(t, err)
	idps := idp.NewRegistryWithStatuses(provs, by, sts, nil, false)

	ph := NewProvidersHandler(f.q, f.sqldb, idps, audit.NewService(f.q))
	sh := NewServicesHandler(f.q, nil, audit.NewService(f.q)).WithProviders(ph)
	r := chi.NewRouter()
	r.Use(withActor)
	r.Get("/admin/providers", ph.HandleList)
	r.Get("/admin/services/{id}/edit", sh.HandleEdit)
	r.Post("/admin/services/{id}/providers", ph.HandleServiceUpdate)
	r.Get("/admin/users/{id}/edit", NewUsersHandler(f.q, f.sqldb, audit.NewService(f.q)).HandleEdit)
	return &provEnv{f3Env: f, idps: idps, mux: r, svcs: sh}
}

func (e *provEnv) do(req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, req)
	return w
}

func (e *provEnv) assignments(t *testing.T, svc string) map[int64]int64 {
	t.Helper()
	rows, err := e.q.ListAssignmentsForService(context.Background(), svc)
	require.NoError(t, err)
	out := map[int64]int64{}
	for _, r := range rows {
		out[r.ProviderID] = r.Position
	}
	return out
}

func (e *provEnv) providerRows(t *testing.T) string {
	t.Helper()
	var s string
	require.NoError(t, e.sqldb.QueryRow(
		`SELECT group_concat(id||slug||display_name||issuer||client_id||ifnull(client_secret_env,'')||active, '|') FROM (SELECT * FROM identity_providers ORDER BY id)`).Scan(&s))
	return s
}

func TestProvidersPage_StatusSecretAndEscaping(t *testing.T) {
	e := newProvEnv(t)
	w := e.do(httptest.NewRequest(http.MethodGet, "/admin/providers", nil))
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()

	assert.Contains(t, body, "Lastet")
	assert.Contains(t, body, "Avvist")
	assert.Contains(t, body, "issuer_not_allowlisted", "avvisningsårsaken vises")
	assert.Contains(t, body, "Inaktiv")
	assert.Contains(t, body, "KAUTH_IDP_ACME", "navnet på variabelen vises")
	assert.Contains(t, body, "satt")
	assert.Contains(t, body, "siste omstart")
	assert.Contains(t, body, "IDENTITY_PROVIDERS.md")
	assert.NotContains(t, body, knownSecret, "hemmelighetsverdien finnes aldri i kroppen")
	assert.Contains(t, body, "<code>svca</code> (2)", "tilordnet tjeneste fra DB")

	assert.Contains(t, body, "&lt;b&gt;Fet&lt;/b&gt; &amp; co")
	assert.NotContains(t, body, "<b>Fet</b>")
}

func TestProvidersPage_RequiresAdminAndRoutesDoNotWriteProviders(t *testing.T) {
	e := newProvEnv(t)
	admin := e.mkUser(t, "konge@example.com")
	_, err := e.sqldb.Exec("UPDATE users SET roles = 'konge' WHERE id = ?", admin.ID)
	require.NoError(t, err)
	issuer := token.NewIssuerForTest()
	cookie := issuer.IssueAdminForTest("konge@example.com", "konge")

	ph := NewProvidersHandler(e.q, e.sqldb, e.idps, audit.NewService(e.q))
	r := chi.NewRouter()
	r.Route("/admin", func(r chi.Router) {
		r.Use(fetchmeta.Middleware)
		r.Group(func(r chi.Router) {
			r.Use(AdminAuthMiddleware(issuer, e.q))
			r.Get("/providers", ph.HandleList)
			r.Post("/services/{id}/providers", ph.HandleServiceUpdate)
		})
	})
	do := func(method, path, site string, withCookie bool, vals url.Values) *httptest.ResponseRecorder {
		var req *http.Request
		if method == http.MethodPost {
			req = formPost(path, vals)
		} else {
			req = httptest.NewRequest(method, path, nil)
		}
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Sec-Fetch-Site", site)
		if withCookie {
			req.AddCookie(&http.Cookie{Name: "admin_token", Value: cookie})
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	w := do(http.MethodGet, "/admin/providers", "same-origin", false, nil)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/admin/login", w.Header().Get("Location"))
	w = do(http.MethodGet, "/admin/providers", "same-origin", true, nil)
	assert.Equal(t, http.StatusOK, w.Code)

	before := e.providerRows(t)
	beforeAssign := e.assignments(t, "svca")
	vals := url.Values{"provider_1": {"on"}, "position_1": {"0"}}
	w = do(http.MethodPost, "/admin/services/svca/providers", "cross-site", true, vals)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, beforeAssign, e.assignments(t, "svca"), "cross-origin endrer ingenting")
	w = do(http.MethodPost, "/admin/services/svca/providers", "same-origin", false, vals)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/admin/login", w.Header().Get("Location"))
	assert.Equal(t, beforeAssign, e.assignments(t, "svca"))

	w = do(http.MethodPost, "/admin/services/svca/providers", "same-origin", true, vals)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, before, e.providerRows(t), "K3: identity_providers er uendret")
}

func TestServiceProviders_SaveAuditAndHotReload(t *testing.T) {
	e := newProvEnv(t)
	require.Len(t, e.idps.ForService("svcb"), 0)
	require.Len(t, e.idps.ForService("svca"), 1)

	w := e.do(formPost("/admin/services/svcb/providers", url.Values{
		"provider_1": {"on"}, "position_1": {"3"},
		"provider_4": {"on"}, "position_4": {"1"},
	}))
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.Equal(t, "/admin/services/svcb/edit", w.Header().Get("Location"))
	assert.Equal(t, map[int64]int64{4: 1, 1: 3}, e.assignments(t, "svcb"))

	_, d := e.auditRow(t, "service_providers_updated")
	assert.Contains(t, d, "service=svcb")
	assert.Contains(t, d, "providers=xss:1,acme:3")
	assert.Contains(t, d, "actor="+testActor)

	got := e.idps.ForService("svcb")
	require.Len(t, got, 2, "gjelder uten ny Registry")
	assert.Equal(t, "xss", got[0].Slug)
	assert.Equal(t, "acme", got[1].Slug)
	assert.Equal(t, 1, e.auditCount(t, "service_providers_updated"))

	// Fjerning: tomt skjema fjerner alle lastede.
	w = e.do(formPost("/admin/services/svcb/providers", url.Values{}))
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Empty(t, e.assignments(t, "svcb"))
	assert.Empty(t, e.idps.ForService("svcb"))
}

func TestServiceProviders_NotLoadedOrInvalid_400NoChange(t *testing.T) {
	e := newProvEnv(t)
	before := e.assignments(t, "svca")
	cases := map[string]url.Values{
		"avvist":       {"provider_1": {"on"}, "provider_2": {"on"}},
		"inaktiv":      {"provider_3": {"on"}},
		"ukjent":       {"provider_99": {"on"}},
		"ikke-tall":    {"provider_abc": {"on"}},
		"dårlig pos":   {"provider_1": {"on"}, "position_1": {"x"}},
		"negativ pos":  {"provider_1": {"on"}, "position_1": {"-1"}},
		"for stor pos": {"provider_1": {"on"}, "position_1": {"100000"}},
	}
	for name, vals := range cases {
		w := e.do(formPost("/admin/services/svca/providers", vals))
		assert.Equal(t, http.StatusBadRequest, w.Code, name)
		assert.Equal(t, before, e.assignments(t, "svca"), name)
	}
	assert.Zero(t, e.auditCount(t, "service_providers_updated"))

	w := e.do(formPost("/admin/services/finnes-ikke/providers", url.Values{}))
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestServiceProviders_KeepsUnloadedAssignment(t *testing.T) {
	e := newProvEnv(t)
	// svca har skjult (id 2, avvist) fra før; lagring fra skjemaet skal ikke slette den.
	w := e.do(formPost("/admin/services/svca/providers", url.Values{"provider_1": {"on"}, "position_1": {"7"}}))
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, map[int64]int64{1: 7, 2: 5}, e.assignments(t, "svca"))
	_, d := e.auditRow(t, "service_providers_updated")
	assert.Contains(t, d, "providers=acme:7")
	assert.Contains(t, d, "kept=skjult:5")
}

func TestServiceEditPage_ShowsLoadedProvidersPrefilled(t *testing.T) {
	e := newProvEnv(t)
	w := e.do(httptest.NewRequest(http.MethodGet, "/admin/services/svca/edit", nil))
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "Identitetsleverandører")
	assert.Contains(t, body, `action="/admin/services/svca/providers"`)
	assert.Regexp(t, `name="provider_1"[^>]*checked`, body)
	assert.Contains(t, body, `name="position_1" min="0" max="9999" value="2"`)
	assert.NotContains(t, body, `name="provider_2"`, "avvist leverandør tilbys ikke")
	assert.NotContains(t, body, `name="provider_3"`)
	assert.Regexp(t, `name="provider_4"[^>]*>`, body)
	assert.Contains(t, body, "&lt;b&gt;Fet&lt;/b&gt; &amp; co")
	assert.Contains(t, body, `href="/admin/providers"`)
}

func TestIdentityList_OIDCNameAndUnknown(t *testing.T) {
	e := newProvEnv(t)
	u := e.mkUser(t, "ola@example.com")
	for _, iss := range []string{"https://xss.example", "https://borte.example"} {
		_, err := e.q.InsertIdentity(context.Background(), gen.InsertIdentityParams{
			UserID: u.ID, Provider: "oidc", Issuer: iss, Subject: "sub-" + iss, CreatedAt: "2026-10-01T10:00:00Z",
		})
		require.NoError(t, err)
	}
	e.addIdentity(t, u.ID, "google", "112233445566778899001")

	w := e.do(httptest.NewRequest(http.MethodGet, "/admin/users/"+id64(u.ID)+"/edit", nil))
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "&lt;b&gt;Fet&lt;/b&gt; &amp; co (xss)")
	assert.Contains(t, body, "ukjent leverandør")
	assert.Contains(t, body, "https://borte.example")
	assert.Contains(t, body, "<td>google</td>")
}

func TestServiceProviders_RemoveUnloaded(t *testing.T) {
	e := newProvEnv(t)

	w := e.do(httptest.NewRequest(http.MethodGet, "/admin/services/svca/edit", nil))
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "Ikke lastet. Beholdes, og virker etter omstart hvis leverandøren lastes.")
	assert.Contains(t, body, "issuer_not_allowlisted")
	assert.Contains(t, body, `name="remove_2"`)

	w = e.do(formPost("/admin/services/svca/providers", url.Values{
		"provider_1": {"on"}, "position_1": {"2"}, "remove_2": {"on"},
	}))
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, map[int64]int64{1: 2}, e.assignments(t, "svca"))
	_, d := e.auditRow(t, "service_providers_updated")
	assert.Contains(t, d, "removed=skjult")
	assert.Contains(t, d, "providers=acme:2")
}

func TestServiceProviders_RemoveInvalid_400(t *testing.T) {
	e := newProvEnv(t)
	before := e.assignments(t, "svca")
	for name, vals := range map[string]url.Values{
		"ikke tilordnet": {"remove_3": {"on"}},
		"lastet":         {"remove_1": {"on"}},
		"ukjent":         {"remove_99": {"on"}},
		"ikke-tall":      {"remove_x": {"on"}},
	} {
		w := e.do(formPost("/admin/services/svca/providers", vals))
		assert.Equal(t, http.StatusBadRequest, w.Code, name)
		assert.Equal(t, before, e.assignments(t, "svca"), name)
	}
}
