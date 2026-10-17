package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/githubtest"
	"github.com/zral/kauth-go/internal/token"
)

// ghLive kobler ekte GitHubHandlers med ekte githubClient til githubtest. Bare
// søm-stubben fra newGHEnv er byttet ut, så PKCE, redirect_uri, hemmelighet og
// engangskode går gjennom samme kode som i drift.
type ghLive struct {
	*ghTestEnv
	gh *githubtest.Server
}

func newGHLive(t *testing.T, mut func(*gen.CreateServiceParams), u githubtest.User) *ghLive {
	t.Helper()
	te := newGHEnv(t, mut, ghIdentity{}, nil)
	gh := githubtest.New(t, githubtest.Options{Secrets: []string{te.cfg.GitHubClientSecret}})
	gh.SetUser(u)
	cfg := te.cfg
	cfg.OIDCAllowInsecure = true
	cfg.GitHubBaseURL, cfg.GitHubAPIURL = gh.URL(), gh.URL()
	te.cfg = cfg
	te.h = NewGitHubHandlers(cfg, te.sqldb, te.q, te.issuer, te.refresh, te.registry(t), te.aud)
	return &ghLive{ghTestEnv: te, gh: gh}
}

var ghNoRedirect = &http.Client{
	Timeout:       5 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// authorize kjører init og sender nettleseren til githubtest. tamper kan endre
// authorize-URL-en på veien. Returnerer state-cookien og callback-URL-en.
func (l *ghLive) authorize(t *testing.T, tamper func(url.Values)) (cookie *http.Cookie, callback *url.URL) {
	t.Helper()
	w := httptest.NewRecorder()
	l.h.InitiateLogin(w, httptest.NewRequest(http.MethodGet, "/github-login?service=klarsyn", nil))
	require.Equal(t, http.StatusFound, w.Code)
	cookie = ghCookie(w, githubStateCookie)
	require.NotNil(t, cookie)
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, l.gh.URL()+"/login/oauth/authorize", loc.Scheme+"://"+loc.Host+loc.Path)
	if tamper != nil {
		q := loc.Query()
		tamper(q)
		loc.RawQuery = q.Encode()
	}
	resp, err := ghNoRedirect.Get(loc.String())
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	callback, err = url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/github-callback", callback.Path)
	return cookie, callback
}

func (l *ghLive) callbackWith(cookie *http.Cookie, callback *url.URL) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, callback.RequestURI(), nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	l.h.HandleCallback(w, req)
	return w
}

// AK5.1: init, authorize, callback og /dispatch-redirect med ekte klient mot
// githubtest gir token for riktig bruker, og engangskoden kan ikke brukes igjen.
func TestGitHubE2E_LoginIssuesTokenForRightUser(t *testing.T) {
	logs := captureLog(t)
	l := newGHLive(t, func(p *gen.CreateServiceParams) { p.AutoRegister = 1 }, githubtest.User{
		ID: []byte("583231"), Name: "Kari Nordmann",
		Emails: []githubtest.Email{{Email: "kari@example.com", Primary: true, Verified: true}},
	})
	cookie, cb := l.authorize(t, nil)
	w := l.callbackWith(cookie, cb)
	lbRequireTokensFor(t, l.lbEnv, w, "klarsyn")
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	claims, err := l.issuer.Verify(loc.Query().Get("token"), token.Expect{TokenUse: "access", Audience: "klarsyn"})
	require.NoError(t, err)
	require.Equal(t, "kari@example.com", claims.Subject)

	var prov, email string
	require.NoError(t, l.sqldb.QueryRow(`SELECT provider, email FROM user_identities WHERE subject = ?`, ghTestSub).Scan(&prov, &email))
	require.Equal(t, "github", prov)
	require.Equal(t, "kari@example.com", email)

	// Kodens andre bruk avvises hos githubtest og gir code_exchange.
	again := l.callbackWith(cookie, cb)
	require.Equal(t, http.StatusSeeOther, again.Code)
	require.Equal(t, "login_failed", ghLoginError(t, again))

	for _, c := range l.gh.Calls() {
		if c.Path == "/login/oauth/access_token" && c.VerifierOK != nil && *c.VerifierOK {
			require.True(t, *c.ClientSecret)
			require.True(t, *c.RedirectURIOK)
		}
	}
	ok := ghAuditFor(t, l.lbEnv, "github_oauth_login")
	require.Len(t, ok, 1)
	rej := ghAuditFor(t, l.lbEnv, "github_oauth_rejected")
	require.Len(t, rej, 1)
	require.Equal(t, "reason=code_exchange", fcDetails(t, rej[0]))

	// Hele flyten, også avvisningen, skal holde hemmelighet, token, kode og
	// GitHub-id ute av loggen.
	out := logs.String()
	require.NotContains(t, out, l.cfg.GitHubClientSecret)
	require.NotContains(t, out, "gho_")
	require.NotContains(t, out, cb.Query().Get("code"))
	require.NotContains(t, out, "583231")
}

// PKCE-feil: code_challenge i authorize-steget byttes, så koden er bundet til
// en annen verifier enn den kauth avleder av state. githubtest avviser da
// utvekslingen, og kauth utsteder ingenting.
func TestGitHubE2E_PKCEMismatchGivesCodeExchange(t *testing.T) {
	l := newGHLive(t, func(p *gen.CreateServiceParams) { p.AutoRegister = 1 }, githubtest.User{
		ID: []byte("583231"), Name: "Kari",
		Emails: []githubtest.Email{{Email: "kari@example.com", Primary: true, Verified: true}},
	})
	cookie, cb := l.authorize(t, func(q url.Values) {
		q.Set("code_challenge", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	})
	w := l.callbackWith(cookie, cb)
	require.Equal(t, "login_failed", ghLoginError(t, w))
	require.Zero(t, l.count(t, `SELECT COUNT(*) FROM refresh_tokens`))
	require.Zero(t, l.count(t, `SELECT COUNT(*) FROM user_identities`))

	var sawBadVerifier bool
	for _, c := range l.gh.Calls() {
		if c.Path == "/login/oauth/access_token" && c.VerifierOK != nil && !*c.VerifierOK {
			sawBadVerifier = true
		}
		require.NotEqual(t, "/user", c.Path, "ingen brukeroppslag uten token")
	}
	require.True(t, sawBadVerifier)
	rej := ghAuditFor(t, l.lbEnv, "github_oauth_rejected")
	require.Len(t, rej, 1)
	require.Equal(t, "reason=code_exchange", fcDetails(t, rej[0]))
}
