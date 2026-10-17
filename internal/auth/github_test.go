package auth

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/idp"
)

const (
	ghTestSub    = "583231"
	ghStateNonce = "gh-nonce"
)

type ghFetchCall struct{ ClientID, Secret, Code, RedirectURI, Verifier string }

type ghTestEnv struct {
	*lbEnv
	h     *GitHubHandlers
	cfg   config.Config
	calls []ghFetchCall
}

// newGHEnv lager tjenesten «klarsyn» (standard) og «andre» (egen auth_host)
// begge med GitHub på. fetchIdentity er byttet ut med en stub som husker kallene.
func newGHEnv(t *testing.T, mut func(*gen.CreateServiceParams), gi ghIdentity, fetchErr error) *ghTestEnv {
	t.Helper()
	t.Setenv("KAUTH_INSECURE_COOKIES", "true")
	e := newLBEnv(t)
	host := "andre.example"
	e.addService(t, "andre", func(p *gen.CreateServiceParams) {
		p.AuthHost = &host
		p.Domain = "andre.test"
		p.IsDefault = 0
		if mut != nil {
			mut(p)
		}
	})
	e.addService(t, "klarsyn", func(p *gen.CreateServiceParams) {
		p.IsDefault = 1
		if mut != nil {
			mut(p)
		}
	})
	_, err := e.sqldb.Exec(`UPDATE services SET auth_github = 1, github_client_id = id || '-gh-id'`)
	require.NoError(t, err)
	cfg := config.Config{
		OIDCStateSecret: []byte("test-secret-32bytes-padded-here!"), GitHubBaseURL: "https://gh.test", GitHubAPIURL: "https://api.gh.test",
		GitHubClientID: "global-id", GitHubClientSecret: "global-secret",
	}
	te := &ghTestEnv{lbEnv: e, cfg: cfg}
	te.h = NewGitHubHandlers(cfg, e.sqldb, e.q, e.issuer, e.refresh, e.registry(t), e.aud)
	te.h.fetchIdentity = func(_ context.Context, clientID, secret, code, redirectURI, verifier string) (ghIdentity, error) {
		te.calls = append(te.calls, ghFetchCall{clientID, secret, code, redirectURI, verifier})
		return gi, fetchErr
	}
	return te
}

func (te *ghTestEnv) state(svcID string) string {
	return signGitHubState(te.cfg.OIDCStateSecret, svcID, ghStateNonce)
}

func (te *ghTestEnv) callback(path, host, cookieState, queryState string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if host != "" {
		req.Host = host
	}
	if cookieState != "" {
		req.AddCookie(&http.Cookie{Name: githubStateCookie, Value: cookieState})
	}
	w := httptest.NewRecorder()
	te.h.HandleCallback(w, req)
	return w
}

func (te *ghTestEnv) ok(svcID string) *httptest.ResponseRecorder {
	st := te.state(svcID)
	return te.callback("/github-callback?code=c&state="+url.QueryEscape(st), "", st, st)
}

func ghLoginError(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	require.Equal(t, http.StatusSeeOther, w.Code)
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/login", loc.Path)
	return loc.Query().Get("error")
}

func ghCookie(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func ghAuditFor(t *testing.T, e *lbEnv, typ string) []gen.AuditEvent {
	t.Helper()
	var out []gen.AuditEvent
	for _, ev := range e.events(t) {
		if ev.EventType == typ {
			out = append(out, ev)
		}
	}
	return out
}

func ghTrusted(email string) ghIdentity {
	return ghIdentity{Subject: ghTestSub, Name: "Kari", Email: email, EmailTrusted: true}
}

func TestGitHubInit_FlagOffGives403(t *testing.T) {
	te := newGHEnv(t, nil, ghIdentity{}, nil)
	_, err := te.sqldb.Exec(`UPDATE services SET auth_github = 0`)
	require.NoError(t, err)
	h := NewGitHubHandlers(te.cfg, te.sqldb, te.q, te.issuer, te.refresh, te.registry(t), te.aud)
	w := httptest.NewRecorder()
	h.InitiateLogin(w, httptest.NewRequest(http.MethodGet, "/github-login?service=klarsyn", nil))
	require.Equal(t, http.StatusForbidden, w.Code)
	require.Nil(t, ghCookie(w, githubStateCookie))
}

func TestGitHubInit_EmptySecretRejectsAndAudits(t *testing.T) {
	te := newGHEnv(t, nil, ghIdentity{}, nil)
	te.h.cfg.GitHubClientSecret = ""
	w := httptest.NewRecorder()
	te.h.InitiateLogin(w, httptest.NewRequest(http.MethodGet, "/github-login?service=klarsyn", nil))
	require.Equal(t, "login_failed", ghLoginError(t, w))
	require.Nil(t, ghCookie(w, githubStateCookie))
	evs := ghAuditFor(t, te.lbEnv, "github_oauth_rejected")
	require.Len(t, evs, 1)
	require.Equal(t, "reason=client_secret_missing", fcDetails(t, evs[0]))
}

func TestGitHubInit_EnvRefMissingRejects(t *testing.T) {
	te := newGHEnv(t, nil, ghIdentity{}, nil)
	_, err := te.sqldb.Exec(`UPDATE services SET github_client_secret_env = 'KAUTH_SVC_GH_NONE'`)
	require.NoError(t, err)
	h := NewGitHubHandlers(te.cfg, te.sqldb, te.q, te.issuer, te.refresh, te.registry(t), te.aud)
	h.getenv = func(string) string { return "" }
	w := httptest.NewRecorder()
	h.InitiateLogin(w, httptest.NewRequest(http.MethodGet, "/github-login?service=klarsyn", nil))
	// Ingen fallback til den globale hemmeligheten når tjenesten har en referanse.
	require.Equal(t, "login_failed", ghLoginError(t, w))
}

func TestGitHubInit_RedirectsWithAllParamsAndCookie(t *testing.T) {
	te := newGHEnv(t, nil, ghIdentity{}, nil)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/github-login?service=klarsyn", nil)
	req.Host = "auth.klarsyn.test"
	te.h.InitiateLogin(w, req)
	require.Equal(t, http.StatusFound, w.Code)
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "https://gh.test/login/oauth/authorize", loc.Scheme+"://"+loc.Host+loc.Path)
	q := loc.Query()
	state := q.Get("state")
	require.Equal(t, "klarsyn-gh-id", q.Get("client_id"), "tjenestens egen client_id går foran den globale")
	require.Equal(t, "https://auth.klarsyn.test/github-callback", q.Get("redirect_uri"))
	require.Equal(t, "read:user user:email", q.Get("scope"))
	require.Equal(t, "select_account", q.Get("prompt"))
	require.Equal(t, "code", q.Get("response_type"))
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	require.Equal(t, "S256", q.Get("code_challenge_method"))
	require.Equal(t, oauth2.S256ChallengeFromVerifier(idp.PKCEVerifier(te.cfg.OIDCStateSecret, state)), q.Get("code_challenge"))
	claims, ok := parseState(te.cfg.OIDCStateSecret, state)
	require.True(t, ok)
	require.True(t, claims.GitHub)
	require.Equal(t, "klarsyn", claims.ServiceID)
	require.False(t, claims.Admin)

	c := ghCookie(w, githubStateCookie)
	require.NotNil(t, c)
	require.Equal(t, state, c.Value)
	require.Equal(t, "/", c.Path)
	require.True(t, c.HttpOnly)
	require.Equal(t, http.SameSiteLaxMode, c.SameSite)
	require.Equal(t, 600, c.MaxAge)
	require.False(t, c.Secure, "KAUTH_INSECURE_COOKIES=true")
}

func TestGitHubInit_SecureCookieByDefaultAndGlobalClientID(t *testing.T) {
	te := newGHEnv(t, nil, ghIdentity{}, nil)
	t.Setenv("KAUTH_INSECURE_COOKIES", "")
	_, err := te.sqldb.Exec(`UPDATE services SET github_client_id = NULL`)
	require.NoError(t, err)
	h := NewGitHubHandlers(te.cfg, te.sqldb, te.q, te.issuer, te.refresh, te.registry(t), te.aud)
	w := httptest.NewRecorder()
	h.InitiateLogin(w, httptest.NewRequest(http.MethodGet, "/github-login?service=klarsyn", nil))
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "global-id", loc.Query().Get("client_id"))
	require.True(t, ghCookie(w, githubStateCookie).Secure)
}

func TestGitHubCallback_LinkedIdentityWithoutEmailLogsIn(t *testing.T) {
	te := newGHEnv(t, nil, ghIdentity{Subject: ghTestSub}, nil)
	user := te.addUser(t, "kari@example.com", "user", "lars")
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := te.q.InsertIdentity(context.Background(), gen.InsertIdentityParams{
		UserID: user.ID, Provider: "github", Issuer: githubIssuer, Subject: ghTestSub, CreatedAt: now, LastUsedAt: &now,
	})
	require.NoError(t, err)
	w := te.ok("klarsyn")
	lbRequireTokensFor(t, te.lbEnv, w, "klarsyn")
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	c := ghCookie(w, githubStateCookie)
	require.NotNil(t, c)
	require.Negative(t, c.MaxAge, "gh_state skal ryddes")
	evs := ghAuditFor(t, te.lbEnv, "github_oauth_login")
	require.Len(t, evs, 1)
	require.Equal(t, "github", *evs[0].AuthMethod)
	require.Equal(t, int64(1), evs[0].Success)
	// Uten betrodd e-post skal ikke en gammel adresse bli stående på koblingen.
	var stored string
	require.NoError(t, te.sqldb.QueryRow(`SELECT email FROM user_identities WHERE subject = ?`, ghTestSub).Scan(&stored))
	require.Empty(t, stored)
}

// finish uten eksplisitt policy gir aldri stille tillit for GitHub.
func TestFinish_GitHubWithoutPolicyFailsClosed(t *testing.T) {
	te := newGHEnv(t, func(p *gen.CreateServiceParams) { p.AutoRegister = 1 }, ghIdentity{}, nil)
	svc, err := te.q.GetServiceByID(context.Background(), "klarsyn")
	require.NoError(t, err)
	w := httptest.NewRecorder()
	te.h.fed.finish(w, httptest.NewRequest(http.MethodGet, "/github-callback", nil), providerGitHub, &svc,
		externalIdentity{Provider: "github", Issuer: githubIssuer, Subject: ghTestSub, Email: "ny@example.com"})
	require.Equal(t, "login_failed", ghLoginError(t, w))
	evs := ghAuditFor(t, te.lbEnv, "github_oauth_rejected")
	require.Len(t, evs, 1)
	require.Equal(t, "reason=internal", fcDetails(t, evs[0]))
	var n int
	require.NoError(t, te.sqldb.QueryRow(`SELECT COUNT(*) FROM user_identities`).Scan(&n))
	require.Zero(t, n)
}

func TestGitHubCallback_PassesExchangeParams(t *testing.T) {
	te := newGHEnv(t, nil, ghIdentity{}, nil)
	st := te.state("klarsyn")
	te.callback("/github-callback?code=kode1&state="+url.QueryEscape(st), "auth.klarsyn.test", st, st)
	require.Len(t, te.calls, 1)
	require.Equal(t, ghFetchCall{
		ClientID: "klarsyn-gh-id", Secret: "global-secret", Code: "kode1",
		RedirectURI: "https://auth.klarsyn.test/github-callback", Verifier: idp.PKCEVerifier(te.cfg.OIDCStateSecret, st),
	}, te.calls[0])
}

func TestGitHubCallback_UnknownWithoutTrustedEmailDenied(t *testing.T) {
	te := newGHEnv(t, func(p *gen.CreateServiceParams) { p.AutoRegister = 1 }, ghIdentity{Subject: ghTestSub, Name: "Kari"}, nil)
	te.addUser(t, "kari@example.com", "user", "lars")
	w := te.ok("klarsyn")
	require.Equal(t, "access_denied", ghLoginError(t, w))
	evs := ghAuditFor(t, te.lbEnv, "github_oauth_rejected")
	require.Len(t, evs, 1)
	require.Equal(t, "reason=email_untrusted", fcDetails(t, evs[0]))
	var n int
	require.NoError(t, te.sqldb.QueryRow(`SELECT COUNT(*) FROM user_identities`).Scan(&n))
	require.Zero(t, n, "ingen kobling og ingen registrering uten betrodd e-post")
}

func TestGitHubCallback_NewUserWithTrustedEmailAutoRegisters(t *testing.T) {
	gi := ghTrusted("ny@example.com")
	gi.Name = "  Kari\x00 Nordmann‮" + strings.Repeat("x", 200)
	te := newGHEnv(t, func(p *gen.CreateServiceParams) { p.AutoRegister = 1 }, gi, nil)
	w := te.ok("klarsyn")
	lbRequireTokensFor(t, te.lbEnv, w, "klarsyn")
	var name string
	require.NoError(t, te.sqldb.QueryRow(`SELECT name FROM users WHERE email = 'ny@example.com'`).Scan(&name))
	require.NotContains(t, name, "\x00")
	require.NotContains(t, name, "\u202E")
	require.LessOrEqual(t, len([]rune(name)), maxDisplayNameLen)
	require.True(t, strings.HasPrefix(name, "Kari Nordmann"))
	var prov, iss string
	require.NoError(t, te.sqldb.QueryRow(`SELECT provider, issuer FROM user_identities WHERE subject = ?`, ghTestSub).Scan(&prov, &iss))
	require.Equal(t, "github", prov)
	require.Equal(t, "https://github.com", iss)
}

func TestGitHubCallback_AutoLinksToExistingGoogleUser(t *testing.T) {
	al := int64(1)
	te := newGHEnv(t, func(p *gen.CreateServiceParams) { p.AutoLink = &al }, ghTrusted("kari@example.com"), nil)
	user := te.addUser(t, "kari@example.com", "user", "lars")
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := te.q.InsertIdentity(context.Background(), gen.InsertIdentityParams{
		UserID: user.ID, Provider: "google", Issuer: googleIssuer, Subject: "g1", CreatedAt: now, LastUsedAt: &now,
	})
	require.NoError(t, err)
	w := te.ok("klarsyn")
	lbRequireTokensFor(t, te.lbEnv, w, "klarsyn")
	var uid int64
	require.NoError(t, te.sqldb.QueryRow(`SELECT user_id FROM user_identities WHERE provider = 'github' AND subject = ?`, ghTestSub).Scan(&uid))
	require.Equal(t, user.ID, uid)
}

func TestGitHubCallback_AutoLinkOffGivesAccountNotLinked(t *testing.T) {
	al := int64(0)
	te := newGHEnv(t, func(p *gen.CreateServiceParams) { p.AutoLink = &al }, ghTrusted("kari@example.com"), nil)
	user := te.addUser(t, "kari@example.com", "user", "lars")
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := te.q.InsertIdentity(context.Background(), gen.InsertIdentityParams{
		UserID: user.ID, Provider: "google", Issuer: googleIssuer, Subject: "g1", CreatedAt: now, LastUsedAt: &now,
	})
	require.NoError(t, err)
	w := te.ok("klarsyn")
	require.Equal(t, "account_not_linked", ghLoginError(t, w))
}

func TestGitHubCallback_DeactivatedUserDenied(t *testing.T) {
	te := newGHEnv(t, nil, ghTrusted("kari@example.com"), nil)
	user := te.addUser(t, "kari@example.com", "user", "lars")
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := te.q.InsertIdentity(context.Background(), gen.InsertIdentityParams{
		UserID: user.ID, Provider: "github", Issuer: githubIssuer, Subject: ghTestSub, CreatedAt: now, LastUsedAt: &now,
	})
	require.NoError(t, err)
	_, err = te.sqldb.Exec(`UPDATE users SET deactivated_at = ?`, now)
	require.NoError(t, err)
	w := te.ok("klarsyn")
	require.Equal(t, "access_denied", ghLoginError(t, w))
	evs := ghAuditFor(t, te.lbEnv, "github_oauth_rejected")
	require.Len(t, evs, 1)
	require.Equal(t, "reason=user_inactive", fcDetails(t, evs[0]))
}

func TestGitHubCallback_MethodDisabledAfterStart(t *testing.T) {
	te := newGHEnv(t, nil, ghTrusted("kari@example.com"), nil)
	_, err := te.sqldb.Exec(`UPDATE services SET auth_github = 0`)
	require.NoError(t, err)
	h := NewGitHubHandlers(te.cfg, te.sqldb, te.q, te.issuer, te.refresh, te.registry(t), te.aud)
	h.fetchIdentity = func(context.Context, string, string, string, string, string) (ghIdentity, error) {
		t.Fatal("ingen kodeutveksling når metoden er av")
		return ghIdentity{}, nil
	}
	te.h = h
	w := te.ok("klarsyn")
	require.Equal(t, "login_failed", ghLoginError(t, w))
	evs := ghAuditFor(t, te.lbEnv, "github_oauth_rejected")
	require.Len(t, evs, 1)
	require.Equal(t, "reason=method_disabled", fcDetails(t, evs[0]))
}

func TestGitHubCallback_ProviderErrorIsSanitizedAndSkipsExchange(t *testing.T) {
	te := newGHEnv(t, nil, ghTrusted("kari@example.com"), nil)
	st := te.state("klarsyn")
	// Mellomrom og «reason=» må ikke kunne forfalske felt i Details.
	bad := "access_denied reason=ok\n" + strings.Repeat("a", 200)
	w := te.callback("/github-callback?error="+url.QueryEscape(bad)+"&state="+url.QueryEscape(st), "", st, st)
	require.Equal(t, "login_failed", ghLoginError(t, w))
	require.Empty(t, te.calls)
	evs := ghAuditFor(t, te.lbEnv, "github_oauth_rejected")
	require.Len(t, evs, 1)
	d := fcDetails(t, evs[0])
	require.True(t, strings.HasPrefix(d, "error=access_denied_reason_ok_"), d)
	require.True(t, strings.HasSuffix(d, " reason=provider_error"), d)
	require.Equal(t, 1, strings.Count(d, "reason="), d)
	require.LessOrEqual(t, len(d), len("error=")+64+len(" reason=provider_error"))
	require.NotContains(t, d, "\n")
}

func TestGitHubCallback_ServiceComesFromStateNotHost(t *testing.T) {
	te := newGHEnv(t, nil, ghIdentity{}, nil)
	st := te.state("klarsyn")
	// Hosten tilhører «andre», staten er utstedt for «klarsyn».
	te.callback("/github-callback?code=c&state="+url.QueryEscape(st), "andre.example", st, st)
	require.Len(t, te.calls, 1)
	require.Equal(t, "klarsyn-gh-id", te.calls[0].ClientID)
}

func TestGitHubCallback_UnknownServiceAndBadState(t *testing.T) {
	te := newGHEnv(t, nil, ghTrusted("kari@example.com"), nil)
	// ukjent tjeneste i gyldig signert state
	st := te.state("finnesikke")
	w := te.callback("/github-callback?code=c&state="+url.QueryEscape(st), "", st, st)
	require.Equal(t, "login_failed", ghLoginError(t, w))
	// state uten cookie, cookie ulik state, feil formål og ødelagt signatur: ingen audit
	good := te.state("klarsyn")
	for name, w := range map[string]*httptest.ResponseRecorder{
		"uten cookie":   te.callback("/github-callback?code=c&state="+url.QueryEscape(good), "", "", good),
		"cookie ulik":   te.callback("/github-callback?code=c&state=x", "", good, good),
		"vanlig state":  te.callback("/github-callback?code=c&state="+url.QueryEscape(SignState(te.cfg.OIDCStateSecret, "klarsyn", "n")), "", SignState(te.cfg.OIDCStateSecret, "klarsyn", "n"), SignState(te.cfg.OIDCStateSecret, "klarsyn", "n")),
		"admin-state":   te.callback("/github-callback?code=c&state="+url.QueryEscape(signAdminState(te.cfg.OIDCStateSecret, "klarsyn", "n")), "", signAdminState(te.cfg.OIDCStateSecret, "klarsyn", "n"), signAdminState(te.cfg.OIDCStateSecret, "klarsyn", "n")),
		"ødelagt state": te.callback("/github-callback?code=c&state="+url.QueryEscape(good+"x"), "", good+"x", good+"x"),
	} {
		require.Equal(t, "login_failed", ghLoginError(t, w), name)
	}
	require.Empty(t, te.calls)
	evs := ghAuditFor(t, te.lbEnv, "github_oauth_rejected")
	require.Len(t, evs, 1)
	require.Equal(t, "reason=unknown_service", fcDetails(t, evs[0]))
}

func TestGitHubCallback_ClientSecretMissing(t *testing.T) {
	te := newGHEnv(t, nil, ghTrusted("kari@example.com"), nil)
	te.h.cfg.GitHubClientSecret = ""
	w := te.ok("klarsyn")
	require.Equal(t, "login_failed", ghLoginError(t, w))
	require.Empty(t, te.calls)
	evs := ghAuditFor(t, te.lbEnv, "github_oauth_rejected")
	require.Len(t, evs, 1)
	require.Equal(t, "reason=client_secret_missing", fcDetails(t, evs[0]))
}

func TestGitHubCallback_FetchErrorsMapToReasons(t *testing.T) {
	for _, tc := range []struct {
		err    error
		reason string
	}{
		{errGHCodeExchange, "code_exchange"},
		{errGHUserFetch, "user_fetch"},
		{errGHMissingID, "missing_id"},
		{errors.New("noe annet"), "user_fetch"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			te := newGHEnv(t, nil, ghIdentity{}, tc.err)
			w := te.ok("klarsyn")
			require.Equal(t, "login_failed", ghLoginError(t, w))
			evs := ghAuditFor(t, te.lbEnv, "github_oauth_rejected")
			require.Len(t, evs, 1)
			require.Equal(t, "reason="+tc.reason, fcDetails(t, evs[0]))
		})
	}
}

// Audit bærer verken GitHub-id, hemmelighet eller kode.
func TestGitHubCallback_AuditNeverHoldsSubjectOrSecrets(t *testing.T) {
	te := newGHEnv(t, func(p *gen.CreateServiceParams) { p.AutoRegister = 1 }, ghTrusted("ny@example.com"), nil)
	lbRequireTokensFor(t, te.lbEnv, te.ok("klarsyn"), "klarsyn")
	for _, ev := range te.events(t) {
		all := ev.EventType
		if ev.Details != nil {
			all += " " + *ev.Details
		}
		for _, secret := range []string{ghTestSub, "global-secret", "klarsyn-gh-id"} {
			require.NotContains(t, all, secret)
		}
	}
}

func TestGitHubFetch_WiresClientEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			require.NoError(t, r.ParseForm())
			require.Equal(t, "ver", r.PostForm.Get("code_verifier"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"bearer"}`))
		case "/user":
			_, _ = w.Write([]byte(`{"id":4711,"name":"Kari"}`))
		case "/user/emails":
			_, _ = w.Write([]byte(`[{"email":"kari@example.com","primary":true,"verified":true}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	te := newGHEnv(t, nil, ghIdentity{}, nil)
	cfg := te.cfg
	cfg.OIDCAllowInsecure = true
	cfg.GitHubBaseURL, cfg.GitHubAPIURL = srv.URL, srv.URL
	h := NewGitHubHandlers(cfg, te.sqldb, te.q, te.issuer, te.refresh, te.registry(t), te.aud)
	gi, err := h.fetch(context.Background(), "id", "sec", "code", "https://x/github-callback", "ver")
	require.NoError(t, err)
	require.Equal(t, ghIdentity{Subject: "4711", Name: "Kari", Email: "kari@example.com", EmailTrusted: true}, gi)
}

func TestCleanDisplayName(t *testing.T) {
	require.Equal(t, "Kari Nordmann", cleanDisplayName("  Kari\x00 Nordmann\n"))
	require.Equal(t, "", cleanDisplayName("\x00\x01 "))
	require.Equal(t, "ab", cleanDisplayName("a\xffb"))
	require.Equal(t, "Kari evil", cleanDisplayName("Kari \u202Eevil\u200F\u2066\u2069\u202A"))
	long := cleanDisplayName(strings.Repeat("æ", 500))
	require.Equal(t, maxDisplayNameLen, len([]rune(long)))
}

func TestProviderErrorToken(t *testing.T) {
	require.Equal(t, "access_denied", providerErrorToken("access_denied"))
	require.Equal(t, "a_b_c", providerErrorToken("a b\nc"))
	require.Len(t, providerErrorToken(strings.Repeat("a", 500)), 64)
}

func TestLoginPage_GitHubButton(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)
	render := func(theme, locale string, on bool) string {
		data := testPageData(t, theme, locale, "/login?service=test")
		data.GitHubEnabled = on
		var out strings.Builder
		require.NoError(t, tmpl.ExecuteTemplate(&out, "login.html", data))
		return out.String()
	}
	for _, theme := range []string{"light", "dark"} {
		for locale, text := range map[string]string{"nb": "Fortsett med GitHub", "en": "Continue with GitHub", "de": "Weiter mit GitHub"} {
			on, off := render(theme, locale, true), render(theme, locale, false)
			require.Contains(t, on, `href="/github-login?service=test"`)
			require.Contains(t, on, text)
			require.NotContains(t, off, "github-login")
			require.NotContains(t, off, "GitHub")
			// etter Microsoft (og før eventuelle generiske leverandører og magic link)
			require.Less(t, strings.Index(on, "/ms-oidc-login"), strings.Index(on, "/github-login"))
			require.Less(t, strings.Index(on, "/github-login"), strings.Index(on, "/magic-login"))
		}
	}
}
