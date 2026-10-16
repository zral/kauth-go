package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/i18n"
	"github.com/zral/kauth-go/internal/mail"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

// Karakteriseringstester for de fire innloggingsmetodene (014 F1). De låser
// dagens svar, cookies, audit og policyhåndhevelse før utstedelsen flyttes til
// ett sted, slik at flyttingen kan bevises uten å endre en eneste test.

const lbPassword = "hunter2"

type lbEnv struct {
	sqldb   *sql.DB
	q       *gen.Queries
	aud     *audit.Service
	issuer  *token.Issuer
	refresh *token.RefreshService
}

func newLBEnv(t *testing.T) *lbEnv {
	t.Helper()
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })
	// :memory: gir en egen database per tilkobling, og audit skriver fra en
	// goroutine.
	sqldb.SetMaxOpenConns(1)
	aud := audit.NewService(q)
	return &lbEnv{sqldb: sqldb, q: q, aud: aud, issuer: token.NewIssuerForTest(), refresh: token.NewRefreshService(sqldb, aud)}
}

// addService lager en tjeneste med alle fire metoder på. mut justerer policyen.
func (e *lbEnv) addService(t *testing.T, id string, mut func(*gen.CreateServiceParams)) {
	t.Helper()
	p := gen.CreateServiceParams{
		ID: id, DisplayName: id, Domain: id + ".test", CallbackUrl: "https://" + id + ".test/cb",
		Theme: "light", AccentColor: "#000", EmailFromName: id,
		AuthGoogle: 1, AuthMicrosoft: 1, AuthMagicLink: 1, AuthPassword: 1, IsDefault: 1,
		JwtCookieName: "auth_token", AccessTokenTtl: "PT15M", Active: 1,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if mut != nil {
		mut(&p)
	}
	require.NoError(t, e.q.CreateService(context.Background(), p))
}

func (e *lbEnv) addUser(t *testing.T, email, roles, orgs string) gen.User {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(lbPassword), bcrypt.MinCost)
	require.NoError(t, err)
	h := string(hash)
	u, err := e.q.CreateUser(context.Background(), gen.CreateUserParams{
		PublicID: token.MustNewPublicID(), Email: email, PasswordHash: &h, Roles: roles, Orgs: orgs,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	require.NoError(t, err)
	return u
}

func (e *lbEnv) service(t *testing.T, id string) gen.Service {
	t.Helper()
	svc, err := e.q.GetServiceByID(context.Background(), id)
	require.NoError(t, err)
	return svc
}

func (e *lbEnv) registry(t *testing.T) *service.Registry {
	t.Helper()
	reg := service.NewRegistry(e.q)
	require.NoError(t, reg.Warmup(context.Background()))
	return reg
}

// events tømmer audit-køen og lister alt. Kalles bare én gang, til slutt i en
// test, siden Close stenger køen.
func (e *lbEnv) events(t *testing.T) []gen.AuditEvent {
	t.Helper()
	return drainAudit(t, e.q, e.aud)
}

// drainAudit tømmer audit-køen og lister alt. Kalles bare én gang per test,
// siden Close stenger køen.
func drainAudit(t *testing.T, q *gen.Queries, aud *audit.Service) []gen.AuditEvent {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, aud.Close(ctx))
	all, err := q.ListAuditEvents(context.Background(), gen.ListAuditEventsParams{Limit: 1000})
	require.NoError(t, err)
	return all
}

func lbRandomToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return "lb-magic-" + hex.EncodeToString(b)
}

// lbNoRejections låser at ingen avslagsrad dukker opp der den ikke finnes i dag.
func lbNoRejections(t *testing.T, events []gen.AuditEvent) {
	t.Helper()
	for _, ev := range events {
		require.NotEqual(t, int64(0), ev.Success, "uventet avslagsrad: %s", ev.EventType)
	}
}

func lbOfType(events []gen.AuditEvent, typ string) []gen.AuditEvent {
	var out []gen.AuditEvent
	for _, ev := range events {
		if ev.EventType == typ {
			out = append(out, ev)
		}
	}
	return out
}

func (e *lbEnv) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, e.sqldb.QueryRow(query, args...).Scan(&n))
	return n
}

// lbMethod er en av de fire innloggingsmetodene, med alt som skiller dem.
type lbMethod struct {
	name        string
	auditType   string
	authMethod  string
	stateCookie string // tom for magic link og passord
	// login kjører en vellykket autentisering av brukeren mot tjenesten og
	// returnerer svaret fra handleren som utsteder tokens.
	login func(t *testing.T, e *lbEnv, svc gen.Service, user gen.User) *httptest.ResponseRecorder
	// denied er svaret på et policyavslag.
	denied func(t *testing.T, w *httptest.ResponseRecorder, svcID, wantDetail string)
	// deniedAudit er audit-typen som policyavslaget skriver (tom: ingen audit).
	deniedAudit string
	// issueFailed er svaret når utstedelsen feiler.
	issueFailed func(t *testing.T, w *httptest.ResponseRecorder, svcID string)
}

func lbMethods() []lbMethod {
	cfg := config.Config{OIDCStateSecret: []byte("test-secret-32bytes-padded-here!")}
	return []lbMethod{
		{
			name: "google", auditType: "google_oidc_login", authMethod: "google", stateCookie: "oidc_state",
			login: func(t *testing.T, e *lbEnv, svc gen.Service, user gen.User) *httptest.ResponseRecorder {
				h := NewGoogleHandlers(cfg, e.sqldb, e.q, e.issuer, e.refresh, e.registry(t), e.aud, nil)
				w := httptest.NewRecorder()
				h.finishCallback(w, httptest.NewRequest(http.MethodGet, "/callback", nil), &svc, false,
					googleClaims{Sub: "sub-" + user.Email, Iss: googleIssuer, Email: user.Email, EmailVerified: true}, "n", "n")
				return w
			},
			denied: func(t *testing.T, w *httptest.ResponseRecorder, svcID, wantDetail string) {
				require.Equal(t, http.StatusSeeOther, w.Code)
				require.Equal(t, "/login?error=access_denied&service="+svcID, w.Header().Get("Location"))
			},
			issueFailed: func(t *testing.T, w *httptest.ResponseRecorder, svcID string) {
				require.Equal(t, http.StatusSeeOther, w.Code)
				require.Equal(t, "/login?error=login_failed&service="+svcID, w.Header().Get("Location"))
				requireRedirectBodyOnly(t, w)
			},
		},
		{
			name: "microsoft", auditType: "microsoft_oidc_login", authMethod: "microsoft", stateCookie: "ms_state",
			login: func(t *testing.T, e *lbEnv, svc gen.Service, user gen.User) *httptest.ResponseRecorder {
				h := NewMicrosoftHandlers(cfg, e.sqldb, e.q, e.issuer, e.refresh, e.registry(t), e.aud)
				cl := msValid(msOrgTid, msBool(true))
				cl.Email = user.Email
				w := httptest.NewRecorder()
				h.finishCallback(w, httptest.NewRequest(http.MethodGet, "/ms-callback", nil), &svc, cl, msTestNon)
				return w
			},
			denied: func(t *testing.T, w *httptest.ResponseRecorder, svcID, wantDetail string) {
				require.Equal(t, http.StatusSeeOther, w.Code)
				require.Equal(t, "/login?error=access_denied&service="+svcID, w.Header().Get("Location"))
			},
			issueFailed: func(t *testing.T, w *httptest.ResponseRecorder, svcID string) {
				require.Equal(t, http.StatusSeeOther, w.Code)
				require.Equal(t, "/login?error=login_failed&service="+svcID, w.Header().Get("Location"))
				requireRedirectBodyOnly(t, w)
			},
		},
		{
			name: "magic", auditType: "magic_link_login", authMethod: "magic_link",
			login: func(t *testing.T, e *lbEnv, svc gen.Service, user gen.User) *httptest.ResponseRecorder {
				tmpl, err := template.ParseGlob("../../templates/*.html")
				require.NoError(t, err)
				h := NewMagicHandlers(config.Config{}, e.q, mail.New(config.Config{SMTPMock: true}), e.issuer, e.refresh, e.registry(t), e.aud, tmpl)
				plain := lbRandomToken(t)
				now := time.Now().UTC()
				sid := svc.ID
				_, err = e.q.InsertMagicTokenLimited(context.Background(), gen.InsertMagicTokenLimitedParams{
					TokenHash: token.HashOpaque(plain), Purpose: token.MagicPurposeService, Email: user.Email, ServiceID: &sid,
					CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(15 * time.Minute).Format(time.RFC3339),
					WindowStart: "9999",
				})
				require.NoError(t, err)
				r := chi.NewRouter()
				r.Post("/magic-login/{token}", h.Redeem)
				req := httptest.NewRequest(http.MethodPost, "/magic-login/"+plain+"?service="+svc.ID, nil)
				req.Header.Set("Sec-Fetch-Site", "same-origin")
				w := httptest.NewRecorder()
				r.ServeHTTP(w, req)
				return w
			},
			denied: func(t *testing.T, w *httptest.ResponseRecorder, svcID, wantDetail string) {
				require.Equal(t, http.StatusFound, w.Code)
				loc, err := url.Parse(w.Header().Get("Location"))
				require.NoError(t, err)
				require.Equal(t, "/magic-login", loc.Path)
				require.Equal(t, "access_denied", loc.Query().Get("error"))
				require.Equal(t, svcID, loc.Query().Get("service"))
			},
			deniedAudit: "login_failed",
			issueFailed: func(t *testing.T, w *httptest.ResponseRecorder, svcID string) {
				require.Equal(t, http.StatusInternalServerError, w.Code)
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				require.Equal(t, i18n.Get(i18n.FromRequest(req)).ErrInternal+"\n", w.Body.String())
			},
		},
		{
			name: "password", auditType: "login_success", authMethod: "password",
			login: func(t *testing.T, e *lbEnv, svc gen.Service, user gen.User) *httptest.ResponseRecorder {
				h := NewPasswordHandlers(e.q, e.issuer, e.refresh, e.registry(t), e.aud, true)
				form := url.Values{"email": {user.Email}, "password": {lbPassword}, "service_id": {svc.ID}}
				req := httptest.NewRequest(http.MethodPost, "/do-login", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				w := httptest.NewRecorder()
				h.DoLogin(w, req)
				return w
			},
			denied: func(t *testing.T, w *httptest.ResponseRecorder, svcID, wantDetail string) {
				require.Equal(t, http.StatusForbidden, w.Code)
				require.Equal(t, wantDetail+"\n", w.Body.String())
			},
			deniedAudit: "login_failed",
			issueFailed: func(t *testing.T, w *httptest.ResponseRecorder, svcID string) {
				require.Equal(t, http.StatusInternalServerError, w.Code)
				require.Equal(t, "intern feil\n", w.Body.String())
			},
		},
	}
}

// S26: dagens suksessrespons, cookies, last_login og audit per metode.
func TestLoginBaseline_SuccessResponse(t *testing.T) {
	for _, m := range lbMethods() {
		t.Run(m.name, func(t *testing.T) {
			e := newLBEnv(t)
			e.addService(t, "klarsyn", nil)
			user := e.addUser(t, "bruker@example.com", "user", "lars")
			svc := e.service(t, "klarsyn")
			require.Nil(t, user.LastLogin)

			w := m.login(t, e, svc, user)

			require.Equal(t, http.StatusFound, w.Code)
			loc, err := url.Parse(w.Header().Get("Location"))
			require.NoError(t, err)
			require.Equal(t, "/dispatch", loc.Path)
			at, rt := loc.Query().Get("token"), loc.Query().Get("rt")
			require.NotEmpty(t, at)
			require.NotEmpty(t, rt)
			require.Equal(t, "klarsyn", loc.Query().Get("service"))
			require.Len(t, loc.Query(), 3, "Location har bare token, rt og service")

			claims, err := e.issuer.Verify(at, token.Expect{TokenUse: "access", Audience: "klarsyn"})
			require.NoError(t, err)
			require.Equal(t, "bruker@example.com", claims.Email)

			rc := cookieNamed(w, "refresh_token")
			require.NotNil(t, rc)
			require.Equal(t, rt, rc.Value)
			require.True(t, rc.HttpOnly)
			require.Equal(t, http.SameSiteNoneMode, rc.SameSite)
			require.Equal(t, 2592000, rc.MaxAge)
			require.Equal(t, "/", rc.Path)
			require.Equal(t, os.Getenv("KAUTH_INSECURE_COOKIES") != "true", rc.Secure)
			require.Equal(t, 1, e.count(t, "SELECT COUNT(*) FROM refresh_tokens WHERE token_hash = ?", token.HashForTest(rt)))

			if m.stateCookie != "" {
				sc := cookieNamed(w, m.stateCookie)
				require.NotNil(t, sc, "state-cookien skal ryddes")
				require.Less(t, sc.MaxAge, 0)
				require.Len(t, w.Result().Cookies(), 2)
			} else {
				require.Len(t, w.Result().Cookies(), 1, "ingen state-cookie for %s", m.name)
			}

			got, err := e.q.GetUserByEmail(context.Background(), "bruker@example.com")
			require.NoError(t, err)
			require.NotNil(t, got.LastLogin)

			events := e.events(t)
			login := lbOfType(events, m.auditType)
			require.Len(t, login, 1)
			require.Equal(t, int64(1), login[0].Success)
			require.NotNil(t, login[0].AuthMethod)
			require.Equal(t, m.authMethod, *login[0].AuthMethod)
			require.NotNil(t, login[0].ServiceID)
			require.Equal(t, "klarsyn", *login[0].ServiceID)
			require.NotNil(t, login[0].Email)
			require.Equal(t, "bruker@example.com", *login[0].Email)
			require.Nil(t, login[0].Details)
			for _, ev := range events {
				require.Equal(t, int64(1), ev.Success, "ingen avvisning: %s", ev.EventType)
			}
		})
	}
}

// S27: feiler utstedelsen, finnes verken refresh-cookie, suksess-audit eller
// last_login. Refresh-utstedelsen tvinges til å feile ved å fjerne tabellen;
// access-tokenet er da allerede laget.
func TestLoginBaseline_IssueFailure(t *testing.T) {
	for _, m := range lbMethods() {
		t.Run(m.name, func(t *testing.T) {
			e := newLBEnv(t)
			e.addService(t, "klarsyn", nil)
			user := e.addUser(t, "bruker@example.com", "user", "lars")
			svc := e.service(t, "klarsyn")
			_, err := e.sqldb.Exec("DROP TABLE refresh_tokens")
			require.NoError(t, err)

			w := m.login(t, e, svc, user)

			m.issueFailed(t, w, "klarsyn")
			require.Nil(t, cookieNamed(w, "refresh_token"))
			require.Empty(t, w.Result().Cookies())
			require.NotContains(t, w.Header().Get("Location"), "/dispatch")
			require.NotContains(t, w.Body.String(), "rt=")

			got, err := e.q.GetUserByEmail(context.Background(), "bruker@example.com")
			require.NoError(t, err)
			require.Nil(t, got.LastLogin)
			events := e.events(t)
			require.Empty(t, lbOfType(events, m.auditType))
			lbNoRejections(t, events)
		})
	}
}

type lbPolicyCase struct {
	name        string
	requireRole string
	enforceOrg  int64
	defaultOrg  string
	roles, orgs string
	allowed     bool
	wantDetail  string
}

var lbPolicyCases = []lbPolicyCase{
	{name: "uten påkrevd rolle", requireRole: "konge", roles: "user", orgs: "lars", wantDetail: "mangler rolle"},
	{name: "sysadmin er ikke admin", requireRole: "admin", roles: "sysadmin", orgs: "lars", wantDetail: "mangler rolle"},
	{name: "feil org", enforceOrg: 1, defaultOrg: "lars", roles: "user", orgs: "annen", wantDetail: "ikke autorisert"},
	{name: "org uten overlapp i delstreng", enforceOrg: 1, defaultOrg: "lars", roles: "user", orgs: "larsen", wantDetail: "ikke autorisert"},
	{name: "rett rolle", requireRole: "konge", roles: "user, konge", orgs: "lars", allowed: true},
	{name: "rett org", enforceOrg: 1, defaultOrg: "lars", roles: "user", orgs: "andre, lars", allowed: true},
	{name: "rett rolle og org", requireRole: "konge", enforceOrg: 1, defaultOrg: "lars", roles: "konge", orgs: "lars", allowed: true},
	{name: "ingen policy", roles: "user", orgs: "annen", allowed: true},
}

// S16 per metode: policyavslag gir dagens svar uten tokens eller refresh-cookie,
// og en bruker som oppfyller policyen slipper inn.
func TestLoginBaseline_PolicyPerMethod(t *testing.T) {
	for _, m := range lbMethods() {
		for _, tc := range lbPolicyCases {
			t.Run(m.name+"/"+tc.name, func(t *testing.T) {
				e := newLBEnv(t)
				e.addService(t, "klarsyn", func(p *gen.CreateServiceParams) {
					if tc.requireRole != "" {
						p.RequireRole = &tc.requireRole
					}
					p.EnforceOrg = tc.enforceOrg
					if tc.defaultOrg != "" {
						p.DefaultOrg = &tc.defaultOrg
					}
				})
				user := e.addUser(t, "bruker@example.com", tc.roles, tc.orgs)

				w := m.login(t, e, e.service(t, "klarsyn"), user)

				events := e.events(t)
				if tc.allowed {
					require.Equal(t, http.StatusFound, w.Code)
					require.True(t, strings.HasPrefix(w.Header().Get("Location"), "/dispatch?token="), w.Header().Get("Location"))
					require.NotNil(t, cookieNamed(w, "refresh_token"))
					require.Len(t, lbOfType(events, m.auditType), 1)
					return
				}
				m.denied(t, w, "klarsyn", tc.wantDetail)
				require.Nil(t, cookieNamed(w, "refresh_token"))
				require.Empty(t, w.Result().Cookies())
				require.NotContains(t, w.Header().Get("Location"), "token=")
				require.Equal(t, 0, e.count(t, "SELECT COUNT(*) FROM refresh_tokens"))
				require.Empty(t, lbOfType(events, m.auditType))
				got, err := e.q.GetUserByEmail(context.Background(), "bruker@example.com")
				require.NoError(t, err)
				require.Nil(t, got.LastLogin)
				if m.deniedAudit == "" {
					lbNoRejections(t, events)
					return
				}
				denied := lbOfType(events, m.deniedAudit)
				require.Len(t, denied, 1)
				require.Equal(t, int64(0), denied[0].Success)
				require.NotNil(t, denied[0].Details)
				require.Equal(t, tc.wantDetail, *denied[0].Details)
			})
		}
	}
}

// S16 som enhet: require_role er eksakt, enforce_org krever default_org.
func TestCheckPolicy_Table(t *testing.T) {
	str := func(s string) *string { return &s }
	for _, tc := range []struct {
		name string
		svc  gen.Service
		user gen.User
		want string
	}{
		{"begge av", gen.Service{}, gen.User{Roles: "user", Orgs: "x"}, ""},
		{"rolle eksakt treff", gen.Service{RequireRole: str("admin")}, gen.User{Roles: "user, admin"}, ""},
		{"rolle mangler", gen.Service{RequireRole: str("admin")}, gen.User{Roles: "user"}, "mangler rolle"},
		{"rolle er delstreng", gen.Service{RequireRole: str("admin")}, gen.User{Roles: "sysadmin"}, "mangler rolle"},
		{"rolle har delstreng", gen.Service{RequireRole: str("admin")}, gen.User{Roles: "admin-readonly"}, "mangler rolle"},
		{"tom require_role krever ingenting", gen.Service{RequireRole: str("")}, gen.User{Roles: "user"}, ""},
		{"enforce_org med treff", gen.Service{EnforceOrg: 1, DefaultOrg: str("lars")}, gen.User{Orgs: "a, lars"}, ""},
		{"enforce_org uten treff", gen.Service{EnforceOrg: 1, DefaultOrg: str("lars")}, gen.User{Orgs: "a"}, "ikke autorisert"},
		{"enforce_org uten default_org", gen.Service{EnforceOrg: 1}, gen.User{Orgs: "a"}, ""},
		{"default_org uten enforce_org", gen.Service{DefaultOrg: str("lars")}, gen.User{Orgs: "a"}, ""},
		{"rolle brutt, org ok", gen.Service{RequireRole: str("admin"), EnforceOrg: 1, DefaultOrg: str("lars")}, gen.User{Roles: "user", Orgs: "lars"}, "mangler rolle"},
		{"rolle ok, org brutt", gen.Service{RequireRole: str("admin"), EnforceOrg: 1, DefaultOrg: str("lars")}, gen.User{Roles: "admin", Orgs: "a"}, "ikke autorisert"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkPolicy(tc.user, &tc.svc)
			if tc.want == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tc.want)
		})
	}
}

// lbTwoServices har "andre" som standardtjeneste og host-eier, og "klarsyn"
// som tjenesten innloggingen faktisk gjelder.
func lbTwoServices(t *testing.T) (*lbEnv, gen.User) {
	t.Helper()
	e := newLBEnv(t)
	host := "andre.example"
	e.addService(t, "andre", func(p *gen.CreateServiceParams) { p.AuthHost = &host; p.Domain = "andre.test" })
	e.addService(t, "klarsyn", func(p *gen.CreateServiceParams) { p.IsDefault = 0 })
	return e, e.addUser(t, "bruker@example.com", "user", "lars")
}

func lbRequireTokensFor(t *testing.T, e *lbEnv, w *httptest.ResponseRecorder, svcID string) {
	t.Helper()
	require.Equal(t, http.StatusFound, w.Code)
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/dispatch", loc.Path)
	require.Equal(t, svcID, loc.Query().Get("service"))
	claims, err := e.issuer.Verify(loc.Query().Get("token"), token.Expect{TokenUse: "access", Audience: svcID})
	require.NoError(t, err)
	require.Equal(t, []string{svcID}, []string(claims.Audience))
	var got string
	require.NoError(t, e.sqldb.QueryRow("SELECT service_id FROM refresh_tokens WHERE token_hash = ?", token.HashForTest(loc.Query().Get("rt"))).Scan(&got))
	require.Equal(t, svcID, got)
}

// S29: tokens og refresh-rad tilhører tjenesten innloggingen er bundet til
// (state, lagret magic-rad, forespurt passordtjeneste), aldri hint, Host eller
// standardtjenesten.
func TestLoginBaseline_TokensBelongToBoundService(t *testing.T) {
	cfg := config.Config{OIDCStateSecret: []byte("test-secret-32bytes-padded-here!")}
	t.Run("google", func(t *testing.T) {
		e, user := lbTwoServices(t)
		h := NewGoogleHandlers(cfg, e.sqldb, e.q, e.issuer, e.refresh, e.registry(t), e.aud, nil)
		h.fetchClaims = func(context.Context, *oauth2.Config, string, string) (googleClaims, string, string) {
			return googleClaims{Sub: "s1", Iss: googleIssuer, Email: user.Email, EmailVerified: true}, "state-nonce", ""
		}
		w := httptest.NewRecorder()
		h.HandleCallback(w, fcCallbackReq("/callback", "oidc_state", SignState(cfg.OIDCStateSecret, "klarsyn", "state-nonce"), "andre.example"))
		lbRequireTokensFor(t, e, w, "klarsyn")
	})
	t.Run("microsoft", func(t *testing.T) {
		e, user := lbTwoServices(t)
		h := NewMicrosoftHandlers(cfg, e.sqldb, e.q, e.issuer, e.refresh, e.registry(t), e.aud)
		cl := msValid(msOrgTid, msBool(true))
		cl.Email = user.Email
		h.fetchClaims = func(context.Context, *oauth2.Config, string) (msClaims, error) { return cl, nil }
		w := httptest.NewRecorder()
		h.HandleCallback(w, fcCallbackReq("/ms-callback", "ms_state", SignState(cfg.OIDCStateSecret, "klarsyn", msTestNon), "andre.example"))
		lbRequireTokensFor(t, e, w, "klarsyn")
	})
	t.Run("magic", func(t *testing.T) {
		e, user := lbTwoServices(t)
		tmpl, err := template.ParseGlob("../../templates/*.html")
		require.NoError(t, err)
		h := NewMagicHandlers(config.Config{}, e.q, mail.New(config.Config{SMTPMock: true}), e.issuer, e.refresh, e.registry(t), e.aud, tmpl)
		plain := lbRandomToken(t)
		now := time.Now().UTC()
		sid := "klarsyn"
		_, err = e.q.InsertMagicTokenLimited(context.Background(), gen.InsertMagicTokenLimitedParams{
			TokenHash: token.HashOpaque(plain), Purpose: token.MagicPurposeService, Email: user.Email, ServiceID: &sid,
			CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(15 * time.Minute).Format(time.RFC3339), WindowStart: "9999",
		})
		require.NoError(t, err)
		r := chi.NewRouter()
		r.Post("/magic-login/{token}", h.Redeem)
		// Hintet peker på den andre tjenesten, og hosten tilhører den.
		req := httptest.NewRequest(http.MethodPost, "/magic-login/"+plain+"?service=andre", nil)
		req.Host = "andre.example"
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		lbRequireTokensFor(t, e, w, "klarsyn")
	})
	t.Run("password", func(t *testing.T) {
		e, user := lbTwoServices(t)
		h := NewPasswordHandlers(e.q, e.issuer, e.refresh, e.registry(t), e.aud, true)
		form := url.Values{"email": {user.Email}, "password": {lbPassword}, "service_id": {"klarsyn"}}
		req := httptest.NewRequest(http.MethodPost, "/do-login", strings.NewReader(form.Encode()))
		req.Host = "andre.example"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.DoLogin(w, req)
		lbRequireTokensFor(t, e, w, "klarsyn")
	})
}

// S30: passordavslag kan ikke skilles fra hverandre, og gir ingen sesjon.
// Tidsbruk (dummy-bcrypt ved ukjent e-post) dekkes ikke her og står i BACKLOG.
func TestPasswordLogin_RejectionsIndistinguishable(t *testing.T) {
	e := newLBEnv(t)
	e.addService(t, "klarsyn", nil)
	e.addService(t, "utenpassord", func(p *gen.CreateServiceParams) { p.AuthPassword = 0; p.IsDefault = 0; p.Domain = "up.test" })
	good := e.addUser(t, "bruker@example.com", "user", "lars")
	// Tom hash: kontoen har aldri satt passord.
	empty := ""
	_, err := e.q.CreateUser(context.Background(), gen.CreateUserParams{PublicID: token.MustNewPublicID(), Email: "tom@example.com", PasswordHash: &empty, Roles: "user", Orgs: "lars", CreatedAt: time.Now().UTC().Format(time.RFC3339)})
	require.NoError(t, err)
	inactive := e.addUser(t, "inaktiv@example.com", "user", "lars")
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = e.q.DeactivateUser(context.Background(), gen.DeactivateUserParams{DeactivatedAt: &now, ID: inactive.ID})
	require.NoError(t, err)

	h := NewPasswordHandlers(e.q, e.issuer, e.refresh, e.registry(t), e.aud, true)
	post := func(email, pw, svc string) *httptest.ResponseRecorder {
		form := url.Values{"email": {email}, "password": {pw}, "service_id": {svc}}
		req := httptest.NewRequest(http.MethodPost, "/do-login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.DoLogin(w, req)
		return w
	}
	cases := map[string]*httptest.ResponseRecorder{
		"feil passord":  post(good.Email, "feil", "klarsyn"),
		"ukjent e-post": post("ukjent@example.com", lbPassword, "klarsyn"),
		"tom hash":      post("tom@example.com", lbPassword, "klarsyn"),
		"deaktivert":    post(inactive.Email, lbPassword, "klarsyn"),
		"tom hash/tomt": post("tom@example.com", "", "klarsyn"),
	}
	for name, w := range cases {
		require.Equal(t, http.StatusUnauthorized, w.Code, name)
		require.Equal(t, "ugyldig e-post eller passord\n", w.Body.String(), name)
		require.Empty(t, w.Result().Cookies(), name)
		require.Empty(t, w.Header().Get("Location"), name)
	}
	off := post(good.Email, lbPassword, "utenpassord")
	require.Equal(t, http.StatusForbidden, off.Code)
	require.Empty(t, off.Result().Cookies())
	require.Equal(t, 0, e.count(t, "SELECT COUNT(*) FROM refresh_tokens"))
	// Kontroll: riktig passord mot tjenesten med passord på slipper inn.
	require.Equal(t, http.StatusFound, post(good.Email, lbPassword, "klarsyn").Code)
}
