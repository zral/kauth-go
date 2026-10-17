package auth

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
)

// En GitHub-identitet gir aldri admin-innlogging, selv for en bruker med
// rollen «konge»: callbacken setter ingen admin-cookie og utsteder bare
// tjenestetokens (aud = tjenesten).
func TestGitHubCallback_NeverGivesAdminSession(t *testing.T) {
	te := newGHEnv(t, func(p *gen.CreateServiceParams) { p.AutoRegister = 1 }, ghTrusted("konge@example.com"), nil)
	te.addUser(t, "konge@example.com", "konge", "lars")
	al := int64(1)
	_, err := te.sqldb.Exec(`UPDATE services SET auto_link = ?`, al)
	require.NoError(t, err)
	h := NewGitHubHandlers(te.cfg, te.sqldb, te.q, te.issuer, te.refresh, te.registry(t), te.aud)
	h.fetchIdentity = te.h.fetchIdentity
	te.h = h
	w := te.ok("klarsyn")
	lbRequireTokensFor(t, te.lbEnv, w, "klarsyn")
	for _, c := range w.Result().Cookies() {
		require.NotEqual(t, "admin_token", c.Name)
	}
	require.NotContains(t, w.Header().Get("Location"), "/admin")
}

// ServeLogin skal koble GitHubEnabled til auth_github-kolonnen, ikke bare
// malen (malen testes med en ferdig bool).
func TestServeLogin_GitHubButtonFollowsServiceFlag(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)
	svcs := []gen.Service{
		{ID: "med", DisplayName: "Med", Domain: "med.test", CallbackUrl: "https://med.test/cb", Active: 1, AuthGithub: 1, AuthMagicLink: 1},
		{ID: "uten", DisplayName: "Uten", Domain: "uten.test", CallbackUrl: "https://uten.test/cb", Active: 1, AuthMagicLink: 1},
	}
	h := &LoginHandler{Registry: service.NewRegistryForTest(svcs), Templates: tmpl}
	body := func(id string) string {
		w := httptest.NewRecorder()
		h.ServeLogin(w, httptest.NewRequest(http.MethodGet, "/login?service="+id, nil))
		require.Equal(t, http.StatusOK, w.Code)
		return w.Body.String()
	}
	require.Contains(t, body("med"), "/github-login?service=med")
	require.NotContains(t, body("uten"), "github-login")
}

// gh_state er engangsbruk også når callbacken avvises før tjenesten er løst
// eller før kodeutvekslingen (ukjent tjeneste, metode av, error i query).
func TestGitHubCallback_StateCookieClearedOnEarlyRejections(t *testing.T) {
	te := newGHEnv(t, nil, ghTrusted("kari@example.com"), nil)
	unknown := te.state("finnesikke")
	good := te.state("klarsyn")
	plain := SignState(te.cfg.OIDCStateSecret, "klarsyn", "n")
	for name, w := range map[string]*httptest.ResponseRecorder{
		"ukjent tjeneste": te.callback("/github-callback?code=c&state="+unknown, "", unknown, unknown),
		"error i query":   te.callback("/github-callback?error=access_denied&state="+good, "", good, good),
		"vanlig state":    te.callback("/github-callback?code=c&state="+plain, "", plain, plain),
	} {
		c := ghCookie(w, githubStateCookie)
		require.NotNil(t, c, name)
		require.Negative(t, c.MaxAge, name)
	}
}
