package auth_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/auth"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

// signAccess lager et access-token med vilkårlig aud, iat og org via testnøkkelen,
// slik at tester kan dekke tokens Issue* aldri produserer (uten aud, gammelt iat).
// Null-tid gir token uten iat.
func signAccess(iss *token.Issuer, aud []string, iat time.Time, orgs ...string) string {
	var iatClaim *jwt.NumericDate
	if !iat.IsZero() {
		iatClaim = jwt.NewNumericDate(iat)
	}
	return iss.SignForTest(token.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://test.example.com",
			Subject:   "sjafor@example.com",
			ID:        "jti-test",
			Audience:  aud,
			IssuedAt:  iatClaim,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
		Email:    "sjafor@example.com",
		Org:      orgs,
		TokenUse: "access",
	})
}

type audFixture struct {
	h    *auth.DispatchHandler
	iss  *token.Issuer
	sqld *sql.DB
	q    *gen.Queries
}

func newAudFixture(t *testing.T, svcs []gen.Service) *audFixture {
	t.Helper()
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })
	// :memory: gir en egen tom database per tilkobling, og audit skriver fra en goroutine.
	sqldb.SetMaxOpenConns(1)
	iss := token.NewIssuerForTest()
	return &audFixture{
		h: &auth.DispatchHandler{
			Registry: service.NewRegistryForTest(svcs), Issuer: iss, Queries: q,
			Audit: audit.NewService(q), DefaultSvcID: "klarsyn",
		},
		iss: iss, sqld: sqldb, q: q,
	}
}

// newOIDCAudFixture har veivakt og minliste i databasen: nivå 0 skriver en
// kode-rad med fremmednøkkel mot services.
func newOIDCAudFixture(t *testing.T) *audFixture {
	t.Helper()
	ctx := context.Background()
	f := newAudFixture(t, nil)
	now := time.Now().UTC().Format(time.RFC3339)
	for _, s := range []struct{ id, domain string }{{"veivakt", "veivakt.app"}, {"minliste", "minliste.efugl.no"}} {
		require.NoError(t, f.q.CreateService(ctx, gen.CreateServiceParams{
			ID: s.id, DisplayName: s.id, Domain: s.domain,
			CallbackUrl: "https://" + s.domain + "/auth/callback",
			Theme:       "light", AccentColor: "#000", EmailFromName: s.id,
			AuthGoogle: 1, JwtCookieName: "auth_token", AccessTokenTtl: "PT15M",
			Active: 1, UpdatedAt: now,
		}))
	}
	// Nivå 0 slår opp brukeren fra tokenets e-post (011 PD12).
	_, err := f.q.CreateUser(ctx, gen.CreateUserParams{
		// Eldre enn alle tokens testene utsteder: nivå 0 avviser tokens fra før e-postepoken.
		PublicID: token.MustNewPublicID(), Email: "sjafor@example.com", Roles: "user", Orgs: "x", CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	})
	require.NoError(t, err)
	reg := service.NewRegistry(f.q)
	require.NoError(t, reg.Warmup(ctx))
	f.h.Registry = reg
	return f
}

func (f *audFixture) dispatchOIDC(t *testing.T, tok, query string) *httptest.ResponseRecorder {
	t.Helper()
	w0 := httptest.NewRecorder()
	auth.SetOIDCAuthorizeCookie(w0, auth.OIDCAuthorizeRequest{
		ClientID: "veivakt", RedirectURI: "https://veivakt.app/auth/callback",
		State: "s", CodeChallenge: "c", CodeChallengeMethod: "S256",
	})
	req := httptest.NewRequest(http.MethodGet, "/dispatch?token="+url.QueryEscape(tok)+query, nil)
	for _, c := range w0.Result().Cookies() {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	f.h.ServeDispatch(w, req)
	return w
}

func (f *audFixture) codeCount(t *testing.T) int {
	t.Helper()
	var n int
	require.NoError(t, f.sqld.QueryRow(`SELECT COUNT(*) FROM authorization_codes`).Scan(&n))
	return n
}

func (f *audFixture) eventsOf(t *testing.T, typ string) []string {
	t.Helper()
	// Audit.Log er asynkron: tøm køen før lesing, så negative asserter er pålitelige.
	// Close er idempotent; Log etter første lesing droppes, så hver test leser etter alle kall.
	require.NoError(t, f.h.Audit.Close(context.Background()))
	all, err := f.q.ListAuditEvents(context.Background(), gen.ListAuditEventsParams{Limit: 100})
	require.NoError(t, err)
	var out []string
	for _, e := range all {
		if e.EventType == typ {
			d := ""
			if e.Details != nil {
				d = *e.Details
			}
			out = append(out, d)
		}
	}
	return out
}

func requireLoginNoCode(t *testing.T, f *audFixture, w *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Equal(t, "/login", w.Header().Get("Location"))
	require.Equal(t, 0, f.codeCount(t), "ingen kode skal lages")
}

// K5: et token for en annen tjeneste veksles ikke til en kode for klienten.
func TestDispatchLevel0_RejectsTokenForOtherService(t *testing.T) {
	f := newOIDCAudFixture(t)
	tok := signAccess(f.iss, []string{"minliste"}, time.Now())
	w := f.dispatchOIDC(t, tok, "&service=veivakt")
	requireLoginNoCode(t, f, w)
	require.Equal(t, []string{"level=0 token_aud=minliste target=veivakt"}, f.eventsOf(t, "dispatch_aud_mismatch"))
	require.Empty(t, f.eventsOf(t, "dispatch_token_stale"))
}

// Et token utstedt før aud ble innført (eller uten aud) avvises på nivå 0.
func TestDispatchLevel0_RejectsTokenWithoutAudience(t *testing.T) {
	f := newOIDCAudFixture(t)
	tok := signAccess(f.iss, nil, time.Now())
	w := f.dispatchOIDC(t, tok, "&service=veivakt")
	requireLoginNoCode(t, f, w)
	require.Equal(t, []string{"level=0 token_aud=- target=veivakt"}, f.eventsOf(t, "dispatch_aud_mismatch"))
}

// K7: grensen er 120 s. 121 s avvises, 119 s gir kode. iat i framtiden tåler 30 s.
func TestDispatchLevel0_StaleBoundary(t *testing.T) {
	cases := []struct {
		name   string
		age    time.Duration
		wantOK bool
	}{
		{"121s er for gammelt", 121 * time.Second, false},
		// iat rundes ned til hele sekunder, og testen kan bruke over ett sekund
		// på en treg maskin. 119 s ga derfor sporadisk 120+ s ved sjekken.
		{"115s er fersk", 115 * time.Second, true},
		{"10s i framtiden er innenfor slingringen", -10 * time.Second, true},
		{"60s i framtiden avvises", -60 * time.Second, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newOIDCAudFixture(t)
			tok := signAccess(f.iss, []string{"veivakt"}, time.Now().Add(-c.age))
			w := f.dispatchOIDC(t, tok, "&service=veivakt")
			if c.wantOK {
				require.True(t, strings.HasPrefix(w.Header().Get("Location"), "https://veivakt.app/auth/callback?code="))
				require.Equal(t, 1, f.codeCount(t))
				require.Empty(t, f.eventsOf(t, "dispatch_token_stale"))
				return
			}
			requireLoginNoCode(t, f, w)
			require.Len(t, f.eventsOf(t, "dispatch_token_stale"), 1)
			require.Empty(t, f.eventsOf(t, "dispatch_aud_mismatch"))
		})
	}
}

func TestDispatchLevel0_StaleAgeIsReported(t *testing.T) {
	f := newOIDCAudFixture(t)
	tok := signAccess(f.iss, []string{"veivakt"}, time.Now().Add(-300*time.Second))
	w := f.dispatchOIDC(t, tok, "&service=veivakt")
	requireLoginNoCode(t, f, w)
	evs := f.eventsOf(t, "dispatch_token_stale")
	require.Len(t, evs, 1)
	require.Regexp(t, `^age_s=(299|300|301)$`, evs[0])
}

func TestDispatchLevel0_RejectsTokenWithoutIAT(t *testing.T) {
	f := newOIDCAudFixture(t)
	tok := signAccess(f.iss, []string{"veivakt"}, time.Time{})
	w := f.dispatchOIDC(t, tok, "&service=veivakt")
	requireLoginNoCode(t, f, w)
	require.Equal(t, []string{"iat=missing"}, f.eventsOf(t, "dispatch_token_stale"))
	require.Empty(t, f.eventsOf(t, "dispatch_aud_mismatch"))
}

func TestDispatchLevel0_HappyPath(t *testing.T) {
	f := newOIDCAudFixture(t)
	svc, err := f.q.GetServiceByID(context.Background(), "veivakt")
	require.NoError(t, err)
	tok, err := f.iss.IssueAccess(gen.User{Email: "sjafor@example.com", Orgs: "x", Roles: "user"}, svc)
	require.NoError(t, err)
	w := f.dispatchOIDC(t, tok, "&service=veivakt")
	require.Equal(t, http.StatusSeeOther, w.Code)
	require.True(t, strings.HasPrefix(w.Header().Get("Location"), "https://veivakt.app/auth/callback?code="))
	require.Equal(t, 1, f.codeCount(t))
	require.Empty(t, f.eventsOf(t, "dispatch_aud_mismatch"))
	require.Empty(t, f.eventsOf(t, "dispatch_token_stale"))
}

// ── Nivå 1-5: audit, ikke blokkering ──

func audServices() []gen.Service {
	svcs := dispatchFixture() // analyse, klarsyn, vinkjeller
	host := "auth.vin.example"
	svcs[2].AuthHost = &host
	return svcs
}

func (f *audFixture) dispatchLevels(tok, query, host, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/dispatch?token="+url.QueryEscape(tok)+query, nil)
	if host != "" {
		req.Host = host
	}
	if cookie != "" {
		req.Header.Set("Cookie", "redirect_uri="+url.QueryEscape(cookie))
	}
	w := httptest.NewRecorder()
	f.h.ServeDispatch(w, req)
	return w
}

// K6: ruting uendret, men avviket mot aud logges med nivået.
func TestDispatchLevels1to5_AudMismatchIsAuditedNotBlocked(t *testing.T) {
	const vin = "https://kjeller.lilleklo.work/auth/callback"
	const kla = "https://klarsyn.net/auth/callback"
	cases := []struct {
		name, query, host, cookie string
		orgs                      []string
		wantLevel                 string
	}{
		{"nivå 1", "", "", vin, nil, "level=1"},
		{"nivå 2", "&service=vinkjeller", "", "", nil, "level=2"},
		{"nivå 3", "", "auth.vin.example", "", nil, "level=3"},
		{"nivå 4", "", "", "", []string{"vinkjeller"}, "level=4"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newAudFixture(t, audServices())
			// aud=klarsyn, men rutingen ender på vinkjeller.
			tok := signAccess(f.iss, []string{"klarsyn"}, time.Now(), c.orgs...)
			w := f.dispatchLevels(tok, c.query, c.host, c.cookie)
			require.Equal(t, http.StatusSeeOther, w.Code)
			require.True(t, strings.HasPrefix(w.Header().Get("Location"), vin+"?token="), w.Header().Get("Location"))
			require.Equal(t, []string{c.wantLevel + " token_aud=klarsyn target=vinkjeller"}, f.eventsOf(t, "dispatch_aud_mismatch"))
		})
	}

	t.Run("nivå 5", func(t *testing.T) {
		f := newAudFixture(t, audServices())
		f.h.DefaultSvcID = "vinkjeller"
		tok := signAccess(f.iss, []string{"klarsyn"}, time.Now())
		w := f.dispatchLevels(tok, "", "", "")
		require.True(t, strings.HasPrefix(w.Header().Get("Location"), vin+"?token="), w.Header().Get("Location"))
		require.Equal(t, []string{"level=5 token_aud=klarsyn target=vinkjeller"}, f.eventsOf(t, "dispatch_aud_mismatch"))
	})

	t.Run("aud lik mål gir ingen event", func(t *testing.T) {
		f := newAudFixture(t, audServices())
		tok := signAccess(f.iss, []string{"klarsyn"}, time.Now())
		w := f.dispatchLevels(tok, "&service=klarsyn", "", "")
		require.True(t, strings.HasPrefix(w.Header().Get("Location"), kla+"?token="))
		require.Empty(t, f.eventsOf(t, "dispatch_aud_mismatch"))
	})
}

// Delt callback (klarsyn og analyse) er ikke avvik, på nivå 1 og 2.
func TestDispatchLevel1_SharedCallbackNoAudit(t *testing.T) {
	const shared = "https://shared.klarsyn.net/auth/callback"
	svcs := dispatchFixture()
	svcs[0].CallbackUrl = shared
	svcs[1].CallbackUrl = shared
	f := newAudFixture(t, svcs)
	tok := signAccess(f.iss, []string{"klarsyn"}, time.Now())

	// Nivå 1: første registrerte tjeneste med callbacken er analyse, aud er klarsyn.
	w := f.dispatchLevels(tok, "&service=klarsyn", "", shared)
	require.True(t, strings.HasPrefix(w.Header().Get("Location"), shared+"?token="))
	// Nivå 2: mål analyse via ?service=, callbacken deles med aud-tjenesten.
	w = f.dispatchLevels(tok, "&service=analyse", "", "")
	require.True(t, strings.HasPrefix(w.Header().Get("Location"), shared+"?token="))
	require.Empty(t, f.eventsOf(t, "dispatch_aud_mismatch"))
}

// Dobbel audit unngås: når innloggingstjenesten er aud, dekker redirect_service_mismatch
// samme faktum på nivå 1. En ?service= utenfor aud gir begge.
func TestDispatchLevel1_NoDoubleAuditWhenLoginServiceIsAud(t *testing.T) {
	const vin = "https://kjeller.lilleklo.work/auth/callback"
	f := newAudFixture(t, audServices())
	tok := signAccess(f.iss, []string{"klarsyn"}, time.Now())
	f.dispatchLevels(tok, "&service=klarsyn", "", vin)
	require.Len(t, f.eventsOf(t, "redirect_service_mismatch"), 1)
	require.Empty(t, f.eventsOf(t, "dispatch_aud_mismatch"))

	// Ny fixture: køen i den første er lukket av lesingen over.
	f = newAudFixture(t, audServices())
	tok = signAccess(f.iss, []string{"klarsyn"}, time.Now())
	f.dispatchLevels(tok, "&service=analyse", "", vin)
	require.Len(t, f.eventsOf(t, "redirect_service_mismatch"), 1)
	require.Len(t, f.eventsOf(t, "dispatch_aud_mismatch"), 1)
}

// K8: exchanged-auditen bærer jti for access- og id-token og familien til koden.
func TestAuthorizationCodeGrant_AuditHasJTIAndFamily(t *testing.T) {
	h, _, q, user, _ := setupReuseTest(t, true)
	verifier, challenge := pkcePair()
	insertAuthCode(t, q, "kode-jti", user.Email, reuseRedirect, challenge, "S256", "openid", "n1")

	w := redeem(h, "kode-jti", reuseRedirect, "veivakt", verifier)
	require.Equal(t, http.StatusOK, w.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))

	// jti leses fra de returnerte tokenene (usignert parse er greit i testen).
	jtiOf := func(tok string) string {
		c := &token.Claims{}
		_, _, err := jwt.NewParser().ParseUnverified(tok, c)
		require.NoError(t, err)
		return c.ID
	}
	at, id := jtiOf(body["access_token"].(string)), jtiOf(body["id_token"].(string))
	require.NotEmpty(t, at)
	require.NotEqual(t, at, id)

	row := codeRow(t, q, "kode-jti")
	require.NotNil(t, row.FamilyID)
	require.Equal(t, "jti_access="+at+" jti_id="+id+" family="+*row.FamilyID, auditDetails(t, q, "authorization_code_exchanged"))
}

// Uten openid-scope finnes ingen id_token: jti_id er "-".
func TestAuthorizationCodeGrant_AuditJTIIDDashWithoutOpenid(t *testing.T) {
	h, _, q, user, _ := setupReuseTest(t, true)
	verifier, challenge := pkcePair()
	insertAuthCode(t, q, "kode-nojti", user.Email, reuseRedirect, challenge, "S256", "email", "")
	w := redeem(h, "kode-nojti", reuseRedirect, "veivakt", verifier)
	require.Equal(t, http.StatusOK, w.Code)
	require.Regexp(t, `^jti_access=\S+ jti_id=- family=\S+$`, auditDetails(t, q, "authorization_code_exchanged"))
}
