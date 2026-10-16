package auth

import (
	"context"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/idp"
)

func renderWithProviders(t *testing.T, theme, locale string, ps []LoginProvider) string {
	t.Helper()
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)
	data := testPageData(t, theme, locale, "/login?service=test")
	data.Providers = ps
	var out strings.Builder
	require.NoError(t, tmpl.ExecuteTemplate(&out, "login.html", data))
	return out.String()
}

func TestLoginTemplate_TwoProvidersInOrder(t *testing.T) {
	out := renderWithProviders(t, "light", "nb", []LoginProvider{{"acme", "Acme SSO"}, {"zed", "Zed"}})
	a := strings.Index(out, `href="/idp/acme/login?service=test"`)
	z := strings.Index(out, `href="/idp/zed/login?service=test"`)
	ms := strings.Index(out, `id="ms-btn"`)
	magic := strings.Index(out, `id="magic-btn"`)
	require.True(t, a > 0 && z > a, "to knapper i rekkefølge")
	assert.True(t, ms < a && z < magic, "etter Microsoft, før magic link")
	assert.Contains(t, out, "Fortsett med Acme SSO")
	assert.Contains(t, out, "Fortsett med Zed")
	assert.Equal(t, 2, strings.Count(out, `class="btn-social idp-btn"`))
}

func TestLoginTemplate_ProviderLocales(t *testing.T) {
	ps := []LoginProvider{{"acme", "Acme"}}
	assert.Contains(t, renderWithProviders(t, "dark", "en", ps), "Continue with Acme")
	assert.Contains(t, renderWithProviders(t, "dark", "de", ps), "Weiter mit Acme")
	assert.Contains(t, renderWithProviders(t, "dark", "nb", ps), "Fortsett med Acme")
}

func TestLoginTemplate_ProviderDisplayNameEscaped(t *testing.T) {
	out := renderWithProviders(t, "light", "en", []LoginProvider{{"x", "<script>alert(1)</script>"}})
	assert.NotContains(t, out, "<script>alert(1)</script>")
	assert.Contains(t, out, "&lt;script&gt;alert(1)&lt;/script&gt;")
}

func TestLoginProviders_OnlyLoadedAndAssigned(t *testing.T) {
	pa := idp.Provider{Slug: "a", DisplayName: "A"}
	pb := idp.Provider{Slug: "b", DisplayName: "B"}
	pc := idp.Provider{Slug: "c", DisplayName: "C"}
	reg := idp.NewRegistry(map[string]idp.Provider{"a": pa, "b": pb, "c": pc},
		map[string][]string{"test": {"b", "ghost", "a"}, "annen": {"c"}}, idp.NewHTTPClient(false), false)
	h := &LoginHandler{IDPs: reg}
	assert.Equal(t, []LoginProvider{{"b", "B"}, {"a", "A"}}, h.loginProviders("test"))
	assert.Nil(t, h.loginProviders("ukjent"))
	assert.Nil(t, (&LoginHandler{}).loginProviders("test"), "nil-register betyr ingen leverandører")
}

func TestGenericRoutesMounted_NotChi404(t *testing.T) {
	f := newGF(t, gfOpts{})
	req := httptest.NewRequest(http.MethodGet, "/idp/x/login", nil).WithContext(context.Background())
	w := f.serve(req)
	assert.NotEqual(t, http.StatusNotFound, w.Code)
}
