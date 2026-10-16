package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/idp"
	"github.com/zral/kauth-go/internal/oidctest"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

const (
	gfHost       = "klarsyn.net"
	gfLeakMarker = "oidctest-hemmelig-tekst-som-ikke-skal-ekkoes"
)

type gfOpts struct {
	trustA       bool
	domainsA     []string
	autoLink     int64
	autoRegister int64
	requireRole  *string
	withDown     bool // leverandør «c» med discovery som svarer 500
}

// gf er en komplett generisk innloggingsflyt mot to fake-IdP-er med egne nøkler.
type gf struct {
	t      *testing.T
	sqldb  *sql.DB
	q      *gen.Queries
	cfg    config.Config
	aud    *audit.Service
	issuer *token.Issuer
	h      *GenericOIDCHandlers
	router http.Handler
	a, b   *oidctest.IdP
	c      *oidctest.IdP
	pa, pb idp.Provider
	svcs   []gen.Service
}

func newGF(t *testing.T, o gfOpts) *gf {
	t.Helper()
	t.Setenv("KAUTH_INSECURE_COOKIES", "true")
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })
	sqldb.SetMaxOpenConns(1)

	ts := time.Now().UTC().Format(time.RFC3339)
	var svcs []gen.Service
	for i, id := range []string{"klarsyn", "annen"} {
		dom := map[string]string{"klarsyn": gfHost, "annen": "annen.net"}[id]
		al := o.autoLink
		require.NoError(t, q.CreateService(context.Background(), gen.CreateServiceParams{
			ID: id, DisplayName: id, Domain: dom, CallbackUrl: "https://" + dom + "/auth/callback",
			Theme: "light", AccentColor: "#000", EmailFromName: id, AutoRegister: o.autoRegister,
			RequireRole: o.requireRole, JwtCookieName: "auth_token", AccessTokenTtl: "PT15M",
			Active: 1, UpdatedAt: ts, AutoLink: &al,
		}))
		svcs = append(svcs, gen.Service{
			ID: id, DisplayName: id, Domain: dom, IsDefault: int64(1 - i), CallbackUrl: "https://" + dom + "/auth/callback",
			Theme: "light", AutoRegister: o.autoRegister, AutoLink: o.autoLink, RequireRole: o.requireRole,
			JwtCookieName: "auth_token", AccessTokenTtl: "PT15M", Active: 1,
		})
	}

	f := &gf{t: t, sqldb: sqldb, q: q, svcs: svcs, issuer: token.NewIssuerForTest()}
	f.cfg = config.Config{OIDCStateSecret: []byte("test-secret-32bytes-padded-here!")}
	f.a = oidctest.New(t, oidctest.Options{ClientID: "client-a", ClientSecret: "secret-a"})
	f.b = oidctest.New(t, oidctest.Options{ClientID: "client-b"})
	scopes := []string{"openid", "email", "profile"}
	f.pa = idp.Provider{ID: 1, Slug: "a", DisplayName: "A", Issuer: f.a.Issuer(), ClientID: "client-a", ClientSecret: "secret-a",
		Scopes: scopes, TrustEmail: o.trustA, EmailDomains: o.domainsA}
	f.pb = idp.Provider{ID: 2, Slug: "b", DisplayName: "B", Issuer: f.b.Issuer(), ClientID: "client-b",
		Scopes: scopes, TrustEmail: true, EmailDomains: []string{"example.test"}}
	providers := map[string]idp.Provider{"a": f.pa, "b": f.pb}
	// «ghost» står i tilordningen men er ikke lastet (inaktiv eller ugyldig rad).
	assigned := []string{"a", "b", "ghost"}
	if o.withDown {
		f.c = oidctest.New(t, oidctest.Options{ClientID: "client-c", DiscoveryMode: oidctest.DiscDown500})
		providers["c"] = idp.Provider{ID: 3, Slug: "c", DisplayName: "C", Issuer: f.c.Issuer(), ClientID: "client-c", Scopes: scopes}
		assigned = append(assigned, "c")
	}
	idps := idp.NewRegistry(providers, map[string][]string{"klarsyn": assigned}, idp.NewHTTPClient(true), true)

	f.aud = audit.NewService(q)
	// Tømmer køen før databasen lukkes, ellers logges skrivefeil etter testen.
	t.Cleanup(func() { _ = f.aud.Close(context.Background()) })
	reg := service.NewRegistryForTest(svcs)
	ref := token.NewRefreshService(sqldb, f.aud)
	f.h = NewGenericOIDCHandlers(f.cfg, sqldb, q, f.issuer, ref, reg, idps, f.aud)
	google := NewGoogleHandlers(f.cfg, sqldb, q, f.issuer, ref, reg, f.aud, nil)
	ms := NewMicrosoftHandlers(f.cfg, sqldb, q, f.issuer, ref, reg, f.aud)

	r := chi.NewRouter()
	r.Get("/idp/{slug}/login", f.h.HandleLogin)
	r.Get("/idp/{slug}/callback", f.h.HandleCallback)
	r.Get("/callback", google.HandleCallback)
	r.Get("/ms-callback", ms.HandleCallback)
	f.router = r
	return f
}

func (f *gf) serve(req *http.Request) *httptest.ResponseRecorder {
	f.t.Helper()
	req.Host = gfHost
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

func (f *gf) user(email, roles string) gen.User {
	f.t.Helper()
	u, err := f.q.CreateUser(context.Background(), gen.CreateUserParams{PublicID: token.MustNewPublicID(), Email: email, Roles: roles, Orgs: "", CreatedAt: t0})
	require.NoError(f.t, err)
	return u
}

func (f *gf) link(userID int64, issuer, sub string) {
	f.t.Helper()
	n, err := f.q.InsertIdentity(context.Background(), gen.InsertIdentityParams{UserID: userID, Provider: "oidc", Issuer: issuer, Subject: sub, CreatedAt: t0})
	require.NoError(f.t, err)
	require.EqualValues(f.t, 1, n)
}

func (f *gf) count(query string, args ...any) int {
	f.t.Helper()
	var n int
	require.NoError(f.t, f.sqldb.QueryRow(query, args...).Scan(&n))
	return n
}

// events tømmer audit-køen og returnerer alt. Kalles etter at flyten er ferdig.
func (f *gf) events() []gen.AuditEvent {
	f.t.Helper()
	return drainAudit(f.t, f.q, f.aud)
}

func (f *gf) rejectedReasons() []string {
	f.t.Helper()
	var out []string
	for _, ev := range lbOfType(f.events(), "oidc_rejected") {
		require.NotNil(f.t, ev.Details)
		out = append(out, *ev.Details)
	}
	return out
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// start kjører HandleLogin og returnerer svaret.
func (f *gf) start(slug, query string) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.serve(httptest.NewRequest(http.MethodGet, "/idp/"+slug+"/login"+query, nil))
}

// authorize følger Location fra init manuelt mot fake-IdP-ens authorize og
// returnerer URL-en leverandøren sender brukeren tilbake til.
func (f *gf) authorize(w *httptest.ResponseRecorder) *url.URL {
	f.t.Helper()
	require.Equal(f.t, http.StatusFound, w.Code, w.Body.String())
	resp, err := noRedirect.Get(w.Header().Get("Location"))
	require.NoError(f.t, err)
	resp.Body.Close()
	require.Equal(f.t, http.StatusFound, resp.StatusCode)
	u, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(f.t, err)
	return u
}

func (f *gf) callbackAt(slug string, u *url.URL, cookie string) *httptest.ResponseRecorder {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/idp/"+slug+"/callback?"+u.RawQuery, nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "idp_state", Value: cookie})
	}
	return f.serve(req)
}

// run er hele veien: init, fake authorize, callback.
func (f *gf) run(fake *oidctest.IdP, slug string, c oidctest.Claims, m oidctest.Mode) *httptest.ResponseRecorder {
	f.t.Helper()
	fake.Next(c, m)
	iw := f.start(slug, "?service=klarsyn")
	sc := cookieNamed(iw, "idp_state")
	require.NotNil(f.t, sc)
	return f.callbackAt(slug, f.authorize(iw), sc.Value)
}

func defaultClaims() oidctest.Claims {
	return oidctest.Claims{Sub: "sub-1", Email: "alice@example.test", EmailVerified: oidctest.EVTrue, Name: "Alice"}
}

func requireDispatch(t *testing.T, w *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	require.Equal(t, http.StatusFound, w.Code, w.Header().Get("Location"))
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/dispatch", loc.Path)
	require.NotEmpty(t, loc.Query().Get("token"))
	return loc
}

func requireLoginError(t *testing.T, w *httptest.ResponseRecorder, code, svc string) {
	t.Helper()
	want := "/login?error=" + code
	if svc != "" {
		want += "&service=" + svc
	}
	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Equal(t, want, w.Header().Get("Location"))
	requireRedirectBodyOnly(t, w)
	require.NotContains(t, w.Header().Get("Location"), "token=")
	require.Nil(t, cookieNamed(w, "refresh_token"), "ingen tokens ved avvisning")
	require.NotContains(t, w.Body.String(), gfLeakMarker)
	require.NotContains(t, w.Header().Get("Location"), gfLeakMarker)
}

// --- Init ---

func TestGenericInit_RedirectsWithAllParams(t *testing.T) {
	f := newGF(t, gfOpts{})
	w1 := f.start("a", "?service=klarsyn")
	require.Equal(t, http.StatusFound, w1.Code)
	loc, err := url.Parse(w1.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, f.a.URL()+"/authorize", loc.Scheme+"://"+loc.Host+loc.Path)
	q := loc.Query()
	require.Equal(t, "code", q.Get("response_type"))
	require.Equal(t, "client-a", q.Get("client_id"))
	require.Equal(t, "http://klarsyn.net/idp/a/callback", q.Get("redirect_uri"))
	require.Equal(t, "openid email profile", q.Get("scope"))
	require.Equal(t, "S256", q.Get("code_challenge_method"))
	require.NotEmpty(t, q.Get("nonce"))

	sc := cookieNamed(w1, "idp_state")
	require.NotNil(t, sc)
	require.Equal(t, q.Get("state"), sc.Value)
	require.True(t, sc.HttpOnly)
	require.Equal(t, http.SameSiteLaxMode, sc.SameSite)
	require.Equal(t, 600, sc.MaxAge)
	require.Equal(t, "/", sc.Path)
	require.False(t, sc.Secure, "KAUTH_INSECURE_COOKIES=true")

	claims, ok := parseState(f.cfg.OIDCStateSecret, sc.Value)
	require.True(t, ok)
	require.Equal(t, stateClaims{ServiceID: "klarsyn", Nonce: q.Get("nonce"), IDP: "a"}, claims)

	sum := sha256.Sum256([]byte(idp.PKCEVerifier(f.cfg.OIDCStateSecret, sc.Value)))
	require.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), q.Get("code_challenge"))

	// Nytt forsøk gir ny state, nonce og challenge.
	w2 := f.start("a", "?service=klarsyn")
	q2, _ := url.ParseQuery(strings.SplitN(w2.Header().Get("Location"), "?", 2)[1])
	require.NotEqual(t, q.Get("state"), q2.Get("state"))
	require.NotEqual(t, q.Get("nonce"), q2.Get("nonce"))
	require.NotEqual(t, q.Get("code_challenge"), q2.Get("code_challenge"))
}

func TestGenericInit_SecureCookieAndHTTPSRedirectURI(t *testing.T) {
	f := newGF(t, gfOpts{})
	t.Setenv("KAUTH_INSECURE_COOKIES", "")
	w := f.start("a", "?service=klarsyn")
	sc := cookieNamed(w, "idp_state")
	require.NotNil(t, sc)
	require.True(t, sc.Secure)
	loc, _ := url.Parse(w.Header().Get("Location"))
	require.Equal(t, "https://klarsyn.net/idp/a/callback", loc.Query().Get("redirect_uri"))
}

func TestGenericInit_RedirectURICookie(t *testing.T) {
	f := newGF(t, gfOpts{})
	w := f.start("a", "?service=klarsyn&redirect_uri="+url.QueryEscape("https://klarsyn.net/app/x"))
	c := cookieNamed(w, "redirect_uri")
	require.NotNil(t, c)
	require.Equal(t, url.QueryEscape("https://klarsyn.net/app/x"), c.Value)
	require.True(t, c.HttpOnly)
	require.Equal(t, 600, c.MaxAge)
	require.Nil(t, cookieNamed(f.start("a", "?service=klarsyn"), "redirect_uri"))

	// Mislykket init setter ingen redirect_uri-cookie.
	ru := "&redirect_uri=" + url.QueryEscape("https://klarsyn.net/app/x")
	for name, q := range map[string]string{
		"ukjent leverandør": "?service=klarsyn" + ru,
		"ikke tilordnet":    "?service=annen" + ru,
	} {
		slug := "a"
		if name == "ukjent leverandør" {
			slug = "finnes-ikke"
		}
		w := f.start(slug, q)
		require.Equal(t, http.StatusSeeOther, w.Code, name)
		require.Nil(t, cookieNamed(w, "redirect_uri"), name)
	}
	fd := newGF(t, gfOpts{withDown: true})
	require.Nil(t, cookieNamed(fd.start("c", "?service=klarsyn"+ru), "redirect_uri"), "discovery-feil")
}

func TestGenericInit_Failures(t *testing.T) {
	f := newGF(t, gfOpts{})
	for _, tc := range []struct{ name, slug, query, svc string }{
		{"ukjent leverandør", "finnes-ikke", "?service=klarsyn", "klarsyn"},
		{"tilordnet men ikke lastet", "ghost", "?service=klarsyn", "klarsyn"},
		{"ikke tilordnet tjenesten", "a", "?service=annen", "annen"},
		{"ugyldig slug", "A_b", "?service=klarsyn", "klarsyn"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := f.start(tc.slug, tc.query)
			requireLoginError(t, w, "login_failed", tc.svc)
			require.Nil(t, cookieNamed(w, "idp_state"))
		})
	}
	require.Empty(t, f.a.Requests(), "ingen kall mot leverandøren for avviste init")

	// Ukjent og inaktiv tjeneste faller til default og kan aldri starte som seg selv.
	w := f.start("a", "?service=inaktiv")
	sc := cookieNamed(w, "idp_state")
	require.NotNil(t, sc)
	claims, ok := parseState(f.cfg.OIDCStateSecret, sc.Value)
	require.True(t, ok)
	require.Equal(t, "klarsyn", claims.ServiceID)

	require.Empty(t, f.rejectedReasons(), "init-feil for ukjent leverandør gir ingen audit")
}

func TestGenericInit_DiscoveryFailureAudited(t *testing.T) {
	f := newGF(t, gfOpts{withDown: true})
	w := f.start("c", "?service=klarsyn")
	requireLoginError(t, w, "login_failed", "klarsyn")
	require.Nil(t, cookieNamed(w, "idp_state"))
	require.Equal(t, []string{"provider=c reason=discovery"}, f.rejectedReasons())
	// En nede leverandør påvirker ikke de andre.
	f2 := newGF(t, gfOpts{withDown: true})
	require.Equal(t, http.StatusFound, f2.start("a", "?service=klarsyn").Code)
}

// --- Callback, suksess ---

func TestGenericCallback_Success_NewUserWithTrust(t *testing.T) {
	f := newGF(t, gfOpts{trustA: true, domainsA: []string{"example.test"}, autoLink: 1, autoRegister: 1})
	w := f.run(f.a, "a", oidctest.Claims{Sub: "sub-1", Email: "ALICE@Example.Test", EmailVerified: oidctest.EVTrue, Name: "Alice"}, oidctest.ModeOK)
	loc := requireDispatch(t, w)
	require.Equal(t, "klarsyn", loc.Query().Get("service"))
	require.NotEmpty(t, loc.Query().Get("rt"))

	claims, err := f.issuer.Verify(loc.Query().Get("token"), token.ExpectAccess)
	require.NoError(t, err)
	require.Contains(t, []string(claims.Audience), "klarsyn")
	require.Equal(t, "alice@example.test", claims.Email)
	_, err = f.issuer.Verify(loc.Query().Get("token"), token.ExpectAdmin)
	require.Error(t, err, "ikke et admin-token")

	require.NotNil(t, cookieNamed(w, "refresh_token"))
	cleared := cookieNamed(w, "idp_state")
	require.NotNil(t, cleared)
	require.Equal(t, -1, cleared.MaxAge)

	var email, prov, issuer, sub string
	require.NoError(t, f.sqldb.QueryRow(`SELECT u.email, i.provider, i.issuer, i.subject FROM user_identities i JOIN users u ON u.id=i.user_id`).Scan(&email, &prov, &issuer, &sub))
	require.Equal(t, []string{"alice@example.test", "oidc", f.a.Issuer(), "sub-1"}, []string{email, prov, issuer, sub})

	logins := lbOfType(f.events(), "oidc_login")
	require.Len(t, logins, 1)
	require.Equal(t, "oidc", *logins[0].AuthMethod)
	require.EqualValues(t, 1, logins[0].Success)
	require.Equal(t, "klarsyn", *logins[0].ServiceID)

	// Kodeutvekslingen brukte PKCE og klienthemmelighet.
	var tokenReqs []oidctest.Request
	for _, r := range f.a.Requests() {
		if r.Path == "/token" {
			tokenReqs = append(tokenReqs, r)
		}
	}
	require.Len(t, tokenReqs, 1)
	require.True(t, tokenReqs[0].PKCEValid)
	require.Equal(t, "basic", tokenReqs[0].ClientAuth)
}

func TestGenericCallback_Success_PublicClientKnownIdentityWithoutTrust(t *testing.T) {
	f := newGF(t, gfOpts{})
	u := f.user("alice@example.test", "user")
	f.link(u.ID, f.a.Issuer(), "sub-1")
	// E-posten avviker og er uverifisert: en kjent identitet trenger ikke tillit.
	w := f.run(f.a, "a", oidctest.Claims{Sub: "sub-1", Email: "annen@elsewhere.test", EmailVerified: oidctest.EVFalse}, oidctest.ModeOK)
	requireDispatch(t, w)
	require.Equal(t, 1, f.count(`SELECT COUNT(*) FROM users`))
	require.Len(t, lbOfType(f.events(), "oidc_login"), 1)
}

func TestGenericCallback_Success_PublicClient(t *testing.T) {
	f := newGF(t, gfOpts{})
	u := f.user("alice@example.test", "user")
	f.link(u.ID, f.b.Issuer(), "sub-1")
	requireDispatch(t, f.run(f.b, "b", defaultClaims(), oidctest.ModeOK))
	for _, r := range f.b.Requests() {
		if r.Path == "/token" {
			require.Equal(t, "none", r.ClientAuth)
			require.True(t, r.PKCEValid)
		}
	}
}

func TestGenericCallback_KnownIdentityWithoutEmail(t *testing.T) {
	f := newGF(t, gfOpts{})
	u := f.user("alice@example.test", "user")
	f.link(u.ID, f.a.Issuer(), "sub-1")
	requireDispatch(t, f.run(f.a, "a", oidctest.Claims{Sub: "sub-1"}, oidctest.ModeOK))
}

func TestGenericCallback_RotateKeyStillSucceeds(t *testing.T) {
	f := newGF(t, gfOpts{})
	u := f.user("alice@example.test", "user")
	f.link(u.ID, f.a.Issuer(), "sub-1")
	requireDispatch(t, f.run(f.a, "a", defaultClaims(), oidctest.ModeOK))
	requireDispatch(t, f.run(f.a, "a", defaultClaims(), oidctest.ModeRotateKey))
}

// --- Callback, avvisning ---

func TestGenericCallback_RejectionModes(t *testing.T) {
	for _, tc := range []struct {
		mode   oidctest.Mode
		reason string
	}{
		{oidctest.ModeWrongIss, "id_token"},
		{oidctest.ModeWrongAud, "id_token"},
		{oidctest.ModeMultiAudBadAzp, "id_token"},
		{oidctest.ModeBadAzp, "id_token"},
		{oidctest.ModeWrongNonce, "nonce"},
		{oidctest.ModeExpired, "id_token"},
		{oidctest.ModeUnknownKid, "id_token"},
		{oidctest.ModeAlgNone, "id_token"},
		{oidctest.ModeAlgHS256, "id_token"},
		{oidctest.ModeNoIDToken, "id_token_missing"},
		{oidctest.ModeAuthorizeError, "provider_error"},
		{oidctest.ModeIssParamWrong, "issuer_param"},
		{oidctest.ModeToken500, "code_exchange"},
	} {
		t.Run(string(tc.mode), func(t *testing.T) {
			f := newGF(t, gfOpts{trustA: true, domainsA: []string{"example.test"}, autoLink: 1, autoRegister: 1})
			w := f.run(f.a, "a", defaultClaims(), tc.mode)
			requireLoginError(t, w, "login_failed", "klarsyn")
			require.Equal(t, []string{"provider=a reason=" + tc.reason}, f.rejectedReasons())
			require.Zero(t, f.count(`SELECT COUNT(*) FROM users`), "ingen bruker opprettet")
			require.Zero(t, f.count(`SELECT COUNT(*) FROM user_identities`))
			require.Empty(t, lbOfType(f.events(), "oidc_login"))
			for _, c := range w.Result().Cookies() {
				require.NotEqual(t, "refresh_token", c.Name)
			}
			cleared := cookieNamed(w, "idp_state")
			require.NotNil(t, cleared, "idp_state ryddes også ved avvisning")
			require.Equal(t, -1, cleared.MaxAge)
		})
	}
}

func TestGenericCallback_TokenSlow_CodeExchangeTimeout(t *testing.T) {
	f := newGF(t, gfOpts{})
	f.a.Next(defaultClaims(), oidctest.ModeTokenSlow)
	iw := f.start("a", "?service=klarsyn")
	sc := cookieNamed(iw, "idp_state")
	u := f.authorize(iw)
	// Kort kontekst i stedet for å vente på klientens tidsavbrudd.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/idp/a/callback?"+u.RawQuery, nil).WithContext(ctx)
	req.AddCookie(&http.Cookie{Name: "idp_state", Value: sc.Value})
	w := f.serve(req)
	requireLoginError(t, w, "login_failed", "klarsyn")
	require.Equal(t, []string{"provider=a reason=code_exchange"}, f.rejectedReasons())
}

func TestGenericCallback_ErrorDescriptionNeverEchoed(t *testing.T) {
	f := newGF(t, gfOpts{})
	w := f.run(f.a, "a", defaultClaims(), oidctest.ModeAuthorizeError)
	requireLoginError(t, w, "login_failed", "klarsyn")
	require.NotContains(t, w.Body.String(), "description")
	for _, h := range w.Result().Header {
		for _, v := range h {
			require.NotContains(t, v, gfLeakMarker)
			require.NotContains(t, v, "access_denied")
		}
	}
	for _, ev := range f.events() {
		if ev.Details != nil {
			require.NotContains(t, *ev.Details, gfLeakMarker)
		}
	}
}

func TestGenericCallback_SubValidation(t *testing.T) {
	for name, sub := range map[string]string{"tom": "", "blank": "   ", "for lang": strings.Repeat("x", 256)} {
		t.Run(name, func(t *testing.T) {
			f := newGF(t, gfOpts{trustA: true, domainsA: []string{"example.test"}, autoLink: 1, autoRegister: 1})
			c := defaultClaims()
			c.Sub = sub
			w := f.run(f.a, "a", c, oidctest.ModeOK)
			requireLoginError(t, w, "login_failed", "klarsyn")
			require.Equal(t, []string{"provider=a reason=missing_sub"}, f.rejectedReasons())
			require.Zero(t, f.count(`SELECT COUNT(*) FROM users`))
		})
	}
	t.Run("255 tegn er greit", func(t *testing.T) {
		f := newGF(t, gfOpts{trustA: true, domainsA: []string{"example.test"}, autoLink: 1, autoRegister: 1})
		c := defaultClaims()
		c.Sub = strings.Repeat("x", 255)
		requireDispatch(t, f.run(f.a, "a", c, oidctest.ModeOK))
	})
}

func TestGenericCallback_SlugInPathDiffersFromState(t *testing.T) {
	f := newGF(t, gfOpts{trustA: true, domainsA: []string{"example.test"}, autoLink: 1, autoRegister: 1})
	f.a.Next(defaultClaims(), oidctest.ModeOK)
	iw := f.start("a", "?service=klarsyn")
	sc := cookieNamed(iw, "idp_state")
	u := f.authorize(iw)
	w := f.callbackAt("b", u, sc.Value)
	requireLoginError(t, w, "login_failed", "klarsyn")
	require.Equal(t, []string{"provider=a reason=unknown_provider"}, f.rejectedReasons())
	for _, r := range f.a.Requests() {
		require.NotEqual(t, "/token", r.Path, "ingen kodeutveksling")
	}
	for _, r := range f.b.Requests() {
		require.NotEqual(t, "/token", r.Path)
	}
}

func TestGenericCallback_ProviderRemovedFromServiceAfterInit(t *testing.T) {
	f := newGF(t, gfOpts{trustA: true, domainsA: []string{"example.test"}, autoLink: 1, autoRegister: 1})
	f.a.Next(defaultClaims(), oidctest.ModeOK)
	iw := f.start("a", "?service=klarsyn")
	sc := cookieNamed(iw, "idp_state")
	u := f.authorize(iw)
	// Tilordningen fjernes mens brukeren er hos leverandøren (state er fortsatt gyldig).
	f.h.idps = idp.NewRegistry(map[string]idp.Provider{"a": f.pa, "b": f.pb}, map[string][]string{"klarsyn": {"b"}}, idp.NewHTTPClient(true), true)
	w := f.callbackAt("a", u, sc.Value)
	requireLoginError(t, w, "login_failed", "klarsyn")
	require.Equal(t, []string{"provider=a reason=unknown_provider"}, f.rejectedReasons())
	for _, r := range f.a.Requests() {
		require.NotEqual(t, "/token", r.Path)
	}
}

func TestGenericCallback_StateForServiceWithoutAssignment(t *testing.T) {
	f := newGF(t, gfOpts{})
	st := signIDPState(f.cfg.OIDCStateSecret, "annen", "n", "a")
	w := f.callbackAt("a", &url.URL{RawQuery: "code=c&state=" + url.QueryEscape(st)}, st)
	requireLoginError(t, w, "login_failed", "annen")
	require.Equal(t, []string{"provider=a reason=unknown_provider"}, f.rejectedReasons())
}

func TestGenericCallback_UnknownService(t *testing.T) {
	f := newGF(t, gfOpts{})
	st := signIDPState(f.cfg.OIDCStateSecret, "borte", "n", "a")
	w := f.callbackAt("a", &url.URL{RawQuery: "code=c&state=" + url.QueryEscape(st)}, st)
	requireLoginError(t, w, "login_failed", "")
	require.Equal(t, []string{"provider=a reason=unknown_service"}, f.rejectedReasons())
}

func TestGenericCallback_BadCookieOrState(t *testing.T) {
	f := newGF(t, gfOpts{})
	s1 := signIDPState(f.cfg.OIDCStateSecret, "klarsyn", "n1", "a")
	s2 := signIDPState(f.cfg.OIDCStateSecret, "klarsyn", "n2", "a")
	for name, tc := range map[string]struct{ cookie, param string }{
		"cookie ulik param": {s1, s2},
		"uten cookie":       {"", s1},
		"søppel":            {"søppel", "søppel"},
		"tom begge":         {"", ""},
	} {
		t.Run(name, func(t *testing.T) {
			w := f.callbackAt("a", &url.URL{RawQuery: "code=c&state=" + url.QueryEscape(tc.param)}, tc.cookie)
			requireLoginError(t, w, "login_failed", "")
		})
	}
	require.Empty(t, f.rejectedReasons(), "ugyldig state sier ikke noe om tjenesten: ingen audit")
}

func TestGenericCallback_ForeignStatePurposesRejected(t *testing.T) {
	f := newGF(t, gfOpts{})
	secret := f.cfg.OIDCStateSecret
	for name, st := range map[string]string{
		"admin-state":  signAdminState(secret, "klarsyn", "n"),
		"google-state": SignState(secret, "klarsyn", "n"),
	} {
		t.Run(name, func(t *testing.T) {
			w := f.callbackAt("a", &url.URL{RawQuery: "code=c&state=" + url.QueryEscape(st)}, st)
			requireLoginError(t, w, "login_failed", "")
		})
	}
	require.Empty(t, f.rejectedReasons())
	require.Empty(t, f.a.Requests())
}

func TestGoogleAndMicrosoftCallbacks_RejectIDPState(t *testing.T) {
	f := newGF(t, gfOpts{})
	st := signIDPState(f.cfg.OIDCStateSecret, "klarsyn", "n", "a")
	for path, cookie := range map[string]string{"/callback": "oidc_state", "/ms-callback": "ms_state"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path+"?code=c&state="+url.QueryEscape(st), nil)
			req.AddCookie(&http.Cookie{Name: cookie, Value: st})
			w := f.serve(req)
			requireLoginError(t, w, "login_failed", "")
			require.Empty(t, w.Result().Cookies())
		})
	}
	var rejected []string
	for _, ev := range f.events() {
		if strings.HasSuffix(ev.EventType, "_rejected") {
			rejected = append(rejected, ev.EventType)
		}
	}
	require.Empty(t, rejected, "ingen audit for ugyldig state")
}

// --- Tillit (K14, K15) ---

func TestGenericCallback_TrustMatrix(t *testing.T) {
	trusted := gfOpts{trustA: true, domainsA: []string{"example.test"}, autoLink: 1, autoRegister: 1}
	untrusted := gfOpts{autoLink: 1, autoRegister: 1}
	noReg := trusted
	noReg.autoRegister = 0
	const (
		denied     = "denied"
		linked     = "linked"
		registered = "registered"
	)
	ev := func(v oidctest.EmailVerified, email string) oidctest.Claims {
		return oidctest.Claims{Sub: "sub-x", Email: email, EmailVerified: v, Name: "X"}
	}
	for _, tc := range []struct {
		name   string
		opts   gfOpts
		claims oidctest.Claims
		want   string
	}{
		{"K14 uten tillit, eksisterende e-post", untrusted, ev(oidctest.EVTrue, "alice@example.test"), denied},
		{"K14 uten tillit, ny e-post med auto_register", untrusted, ev(oidctest.EVTrue, "bob@example.test"), denied},
		{"verified=false", trusted, ev(oidctest.EVFalse, "alice@example.test"), denied},
		{"verified=\"false\"", trusted, ev(oidctest.EVStringFalse, "alice@example.test"), denied},
		{"verified mangler", trusted, ev(oidctest.EVOmit, "alice@example.test"), denied},
		{"verified=false, ny e-post", trusted, ev(oidctest.EVFalse, "bob@example.test"), denied},
		{"domene utenfor listen", trusted, ev(oidctest.EVTrue, "alice@other.test"), denied},
		{"subdomene av domenet", trusted, ev(oidctest.EVTrue, "alice@sub.example.test"), denied},
		{"domenet som lokaldel", trusted, ev(oidctest.EVTrue, "alice@example.test@evil.test"), denied},
		{"domenet som suffiks", trusted, ev(oidctest.EVTrue, "alice@notexample.test"), denied},
		{"domene i listen, kobling", trusted, ev(oidctest.EVTrue, "alice@example.test"), linked},
		{"verified som streng true", trusted, ev(oidctest.EVStringTrue, "alice@example.test"), linked},
		{"normalisering", trusted, ev(oidctest.EVTrue, "ALICE@Example.TEST"), linked},
		{"domene i listen, registrering", trusted, ev(oidctest.EVTrue, "bob@example.test"), registered},
		{"trust uten auto_register, ny e-post", noReg, ev(oidctest.EVTrue, "bob@example.test"), denied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newGF(t, tc.opts)
			alice := f.user("alice@example.test", "user")
			w := f.run(f.a, "a", tc.claims, oidctest.ModeOK)
			events := f.events()
			switch tc.want {
			case denied:
				requireLoginError(t, w, "access_denied", "klarsyn")
				require.Equal(t, 1, f.count(`SELECT COUNT(*) FROM users`), "ingen ny bruker")
				require.Zero(t, f.count(`SELECT COUNT(*) FROM user_identities`))
				require.Empty(t, lbOfType(events, "identity_linked"))
				require.Empty(t, lbOfType(events, "oidc_login"))
			case linked:
				requireDispatch(t, w)
				require.Equal(t, 1, f.count(`SELECT COUNT(*) FROM users`))
				require.Equal(t, 1, f.count(`SELECT COUNT(*) FROM user_identities WHERE user_id=? AND provider='oidc' AND issuer=? AND email='alice@example.test'`, alice.ID, f.a.Issuer()))
				require.Len(t, lbOfType(events, "identity_linked"), 1)
			case registered:
				requireDispatch(t, w)
				require.Equal(t, 2, f.count(`SELECT COUNT(*) FROM users`))
				require.Equal(t, 1, f.count(`SELECT COUNT(*) FROM users u JOIN user_identities i ON i.user_id=u.id WHERE u.email='bob@example.test'`))
			}
		})
	}
}

func TestGenericCallback_TrustedProviderWithoutEmail(t *testing.T) {
	f := newGF(t, gfOpts{trustA: true, domainsA: []string{"example.test"}, autoLink: 1, autoRegister: 1})
	w := f.run(f.a, "a", oidctest.Claims{Sub: "sub-1", EmailVerified: oidctest.EVTrue}, oidctest.ModeOK)
	requireLoginError(t, w, "login_failed", "klarsyn")
	require.Equal(t, []string{"provider=a reason=email_missing"}, f.rejectedReasons())
	require.Zero(t, f.count(`SELECT COUNT(*) FROM users`))
}

func TestGenericCallback_SameSubFromTwoProvidersGivesTwoIdentities(t *testing.T) {
	f := newGF(t, gfOpts{trustA: true, domainsA: []string{"example.test"}, autoLink: 1, autoRegister: 1})
	requireDispatch(t, f.run(f.a, "a", defaultClaims(), oidctest.ModeOK))
	requireDispatch(t, f.run(f.b, "b", defaultClaims(), oidctest.ModeOK))
	require.Equal(t, 2, f.count(`SELECT COUNT(*) FROM user_identities WHERE subject='sub-1' AND provider='oidc'`))
	require.Equal(t, 2, f.count(`SELECT COUNT(DISTINCT issuer) FROM user_identities`))
}

// --- checkPolicy og admin (K18) ---

func TestGenericCallback_CheckPolicyApplies(t *testing.T) {
	role := "admin"
	opts := gfOpts{trustA: true, domainsA: []string{"example.test"}, autoLink: 1, autoRegister: 0, requireRole: &role}
	t.Run("mangler rolle", func(t *testing.T) {
		f := newGF(t, opts)
		f.user("alice@example.test", "user")
		w := f.run(f.a, "a", defaultClaims(), oidctest.ModeOK)
		requireLoginError(t, w, "access_denied", "klarsyn")
		require.Empty(t, lbOfType(f.events(), "oidc_login"))
	})
	t.Run("har rolle", func(t *testing.T) {
		f := newGF(t, opts)
		f.user("alice@example.test", "user, admin")
		requireDispatch(t, f.run(f.a, "a", defaultClaims(), oidctest.ModeOK))
	})
}

func TestGenericCallback_KongeGetsNoAdminAccess(t *testing.T) {
	f := newGF(t, gfOpts{trustA: true, domainsA: []string{"example.test"}, autoLink: 1})
	konge := f.user("alice@example.test", "user, konge")
	usersBefore := f.count(`SELECT COUNT(*) FROM users WHERE admin_bound_at IS NULL`)

	w := f.run(f.a, "a", defaultClaims(), oidctest.ModeOK)
	loc := requireDispatch(t, w)
	require.Nil(t, cookieNamed(w, "admin_token"))
	for _, c := range w.Result().Cookies() {
		require.NotEqual(t, "/admin", c.Path)
	}
	_, err := f.issuer.Verify(loc.Query().Get("token"), token.ExpectAdmin)
	require.Error(t, err)

	require.Zero(t, f.count(`SELECT COUNT(*) FROM user_identities WHERE admin_ok=1`))
	require.Equal(t, 1, f.count(`SELECT COUNT(*) FROM user_identities WHERE user_id=? AND provider='oidc' AND admin_ok=0`, konge.ID))
	require.Equal(t, usersBefore, f.count(`SELECT COUNT(*) FROM users WHERE admin_bound_at IS NULL`))
	require.Empty(t, lbOfType(f.events(), "admin_google_login"))

	// Skjemaet nekter admin_ok på en oidc-identitet selv med direkte SQL.
	_, err = f.sqldb.Exec(`UPDATE user_identities SET admin_ok=1 WHERE provider='oidc'`)
	require.Error(t, err)
}

// --- F3-review: all trafikk mot leverandøren går via idp.Registry ---

var directCallRe = regexp.MustCompile(`([A-Za-z0-9_.]+)\.(Exchange|UserInfo)\(`)

// directProviderCalls finner kall til Exchange( og UserInfo( der mottakeren
// ikke er idps. Kommentarlinjer hoppes over.
func directProviderCalls(src string) []string {
	var bad []string
	for _, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		for _, m := range directCallRe.FindAllStringSubmatch(line, -1) {
			if m[1] != "idps" && !strings.HasSuffix(m[1], ".idps") {
				bad = append(bad, strings.TrimSpace(line))
			}
		}
	}
	return bad
}

func TestDirectProviderCallScanner(t *testing.T) {
	require.NotEmpty(t, directProviderCalls("\ttok, err := oauthCfg.Exchange(ctx, code)"))
	require.NotEmpty(t, directProviderCalls("\tx, err := provider.UserInfo(ctx, ts)"))
	require.NotEmpty(t, directProviderCalls("\ttok, err := cfg.Exchange(ctx, code)"))
	require.Empty(t, directProviderCalls("\ttok, err := h.idps.Exchange(ctx, slug, cfg, code)"))
	require.Empty(t, directProviderCalls("\t// oauthCfg.Exchange( er forbudt"))
}

func TestGenericHandlerOnlyCallsProviderThroughRegistry(t *testing.T) {
	src, err := os.ReadFile("oidc_generic.go")
	require.NoError(t, err)
	require.Empty(t, directProviderCalls(string(src)))
	require.Contains(t, string(src), "h.idps.Exchange(", "skanningen må treffe den faktiske kodeutvekslingen")

	// Ingen annen fil i pakken kan bruke den generiske stien uten registeret.
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") || name == "google.go" || name == "microsoft.go" {
			continue
		}
		b, err := os.ReadFile(name)
		require.NoError(t, err)
		require.Empty(t, directProviderCalls(string(b)), name)
	}
}

func TestAzpOK(t *testing.T) {
	for _, tc := range []struct {
		name string
		aud  []string
		azp  string
		want bool
	}{
		{"én aud, ingen azp", []string{"c"}, "", true},
		{"én aud, azp lik", []string{"c"}, "c", true},
		{"én aud, azp feil", []string{"c"}, "x", false},
		{"flere aud, azp lik", []string{"c", "x"}, "c", true},
		{"flere aud, azp feil", []string{"c", "x"}, "x", false},
		{"flere aud, azp mangler", []string{"c", "x"}, "", false},
	} {
		require.Equal(t, tc.want, azpOK(tc.aud, tc.azp, "c"), tc.name)
	}
}

func TestGenericCallback_IssParamRequiredWhenAdvertised(t *testing.T) {
	newAdv := func(t *testing.T, issParam bool) *gf {
		f := newGF(t, gfOpts{})
		f.a.Close()
		f.a = oidctest.New(t, oidctest.Options{ClientID: "client-a", ClientSecret: "secret-a", AdvertiseIssParam: true, IssParam: issParam})
		f.pa.Issuer = f.a.Issuer()
		f.h.idps = idp.NewRegistry(map[string]idp.Provider{"a": f.pa, "b": f.pb}, map[string][]string{"klarsyn": {"a", "b"}}, idp.NewHTTPClient(true), true)
		u := f.user("alice@example.test", "user")
		f.link(u.ID, f.a.Issuer(), "sub-1")
		return f
	}
	t.Run("iss mangler", func(t *testing.T) {
		f := newAdv(t, false)
		w := f.run(f.a, "a", defaultClaims(), oidctest.ModeOK)
		requireLoginError(t, w, "login_failed", "klarsyn")
		require.Equal(t, []string{"provider=a reason=issuer_param"}, f.rejectedReasons())
		for _, r := range f.a.Requests() {
			require.NotEqual(t, "/token", r.Path)
		}
	})
	t.Run("iss til stede", func(t *testing.T) {
		f := newAdv(t, true)
		requireDispatch(t, f.run(f.a, "a", defaultClaims(), oidctest.ModeOK))
	})
	t.Run("ikke annonsert, iss mangler er greit", func(t *testing.T) {
		f := newGF(t, gfOpts{})
		u := f.user("alice@example.test", "user")
		f.link(u.ID, f.a.Issuer(), "sub-1")
		requireDispatch(t, f.run(f.a, "a", defaultClaims(), oidctest.ModeOK))
	})
}

// Unicode-folding i NormalizeEmail må aldri gi tillit til en annen adresse.
func TestGenericCallback_UnicodeLookalikeEmailNeverTrusted(t *testing.T) {
	for name, email := range map[string]string{
		"Kelvin-tegn":       "\u212Aari@korp.no",
		"İ":                 "kar\u0130@korp.no",
		"to @":              "a@x@korp.no",
		"fullbredde @":      "kari\uFF20korp.no",
		"fullbredde domene": "kari@korp.n\uFF4F",
		"NBSP til slutt":    "kari@korp.no\u00A0",
		"NBSP først":        "\u00A0kari@korp.no",
		"mellomrom først":   " kari@korp.no",
		"tab til slutt":     "kari@korp.no\t",
		"ideografisk rom":   "kari@korp.no\u3000",
	} {
		t.Run(name, func(t *testing.T) {
			f := newGF(t, gfOpts{trustA: true, domainsA: []string{"korp.no"}, autoLink: 1, autoRegister: 1})
			kari := f.user("kari@korp.no", "user")
			w := f.run(f.a, "a", oidctest.Claims{Sub: "sub-u", Email: email, EmailVerified: oidctest.EVTrue}, oidctest.ModeOK)
			requireLoginError(t, w, "access_denied", "klarsyn")
			require.Equal(t, 1, f.count(`SELECT COUNT(*) FROM users`))
			require.Zero(t, f.count(`SELECT COUNT(*) FROM user_identities WHERE user_id=?`, kari.ID))
			require.Contains(t, f.rejectedReasons(), "provider=a reason=email_untrusted")
		})
	}
	t.Run("vanlig ASCII er fortsatt tillatt", func(t *testing.T) {
		f := newGF(t, gfOpts{trustA: true, domainsA: []string{"korp.no"}, autoLink: 1, autoRegister: 1})
		f.user("kari@korp.no", "user")
		requireDispatch(t, f.run(f.a, "a", oidctest.Claims{Sub: "sub-u", Email: "Kari@Korp.no", EmailVerified: oidctest.EVTrue}, oidctest.ModeOK))
	})
}

func TestGenericCallback_UntrustedAuditedAndStoresNormalizedEmail(t *testing.T) {
	f := newGF(t, gfOpts{autoLink: 1, autoRegister: 1})
	w := f.run(f.a, "a", oidctest.Claims{Sub: "sub-n", Email: " ALICE@Example.Test ", EmailVerified: oidctest.EVTrue}, oidctest.ModeOK)
	requireLoginError(t, w, "access_denied", "klarsyn")
	require.Equal(t, []string{"provider=a reason=email_untrusted"}, f.rejectedReasons())

	// Kjent identitet uten tillit lagrer den normaliserte e-posten.
	f2 := newGF(t, gfOpts{})
	u := f2.user("alice@example.test", "user")
	f2.link(u.ID, f2.a.Issuer(), "sub-n")
	requireDispatch(t, f2.run(f2.a, "a", oidctest.Claims{Sub: "sub-n", Email: " ALICE@Example.Test ", EmailVerified: oidctest.EVTrue}, oidctest.ModeOK))
	var stored string
	require.NoError(t, f2.sqldb.QueryRow(`SELECT email FROM user_identities WHERE subject='sub-n'`).Scan(&stored))
	require.Equal(t, "alice@example.test", stored)
}

// finish uten eksplisitt policy gir aldri stille tillit for generisk OIDC.
func TestFinish_GenericOIDCWithoutPolicyFailsClosed(t *testing.T) {
	f := newGF(t, gfOpts{autoLink: 1, autoRegister: 1})
	f.user("alice@example.test", "user")
	w := httptest.NewRecorder()
	f.h.fed.finish(w, httptest.NewRequest(http.MethodGet, "/idp/a/callback", nil), providerOIDC, &f.svcs[0],
		externalIdentity{Provider: "oidc", Issuer: f.a.Issuer(), Subject: "s", Email: "alice@example.test"})
	requireLoginError(t, w, "login_failed", "klarsyn")
	require.Equal(t, []string{"reason=internal"}, f.rejectedReasons())
	require.Zero(t, f.count(`SELECT COUNT(*) FROM user_identities`))
	require.Equal(t, 1, f.count(`SELECT COUNT(*) FROM users`))
}
