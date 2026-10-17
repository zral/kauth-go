//go:build e2e

// Pakken kjører hele OIDC-reisen i prosess: klient, kauth-ruter og fake
// leverandør på loopback. Ingen nett. Ruteren settes opp av main.go og kan ikke
// kalles herfra, så den bygges her med de samme handlerne og midlene for rutene
// flyten bruker.
//
// Avvik fra main.go: ingen statiske filer, legacy-redirects, admin, magic link,
// Google/Microsoft eller /api/me, og /token har CORS uten tillatte origins
// (klienten sender ingen Origin-header, så CORS-laget er uten virkning her).
// Ingen av dem ligger på flytens vei. Issuer er NewIssuerForTest (egen nøkkel,
// annen issuer-streng enn i drift), som bare påvirker verdiene som sjekkes,
// ikke stegene.
package e2e

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/auth"
	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/idp"
	"github.com/zral/kauth-go/internal/oidctest"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

const (
	clientID    = "e2eapp"
	redirectURI = "https://app.e2e.test/auth/callback"
	userEmail   = "alice@example.test"
)

func TestE2E_LoginCodeTokenRefreshReuse(t *testing.T) {
	// Test-serveren er http på loopback; uten dette får cookiene Secure-flagget
	// og jar-en sender dem aldri tilbake.
	t.Setenv("KAUTH_INSECURE_COOKIES", "true")
	ctx := context.Background()

	// --- Oppsett: DB, tjeneste, bruker, fake-IdP ---
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })
	// :memory: er én database per tilkobling; én tilkobling gir alle handlerne
	// samme database.
	sqldb.SetMaxOpenConns(1)

	now := time.Now().UTC().Format(time.RFC3339)
	require.NoError(t, q.CreateService(ctx, gen.CreateServiceParams{
		ID: clientID, DisplayName: "E2E", Domain: "app.e2e.test", CallbackUrl: redirectURI,
		Theme: "light", AccentColor: "#000", EmailFromName: "E2E",
		JwtCookieName: "auth_token", AccessTokenTtl: "PT15M", Active: 1, UpdatedAt: now,
	}))
	user, err := q.CreateUser(ctx, gen.CreateUserParams{
		PublicID: token.MustNewPublicID(), Email: userEmail, Roles: "user", Orgs: "", CreatedAt: now,
	})
	require.NoError(t, err)

	fake := oidctest.New(t, oidctest.Options{ClientID: "client-e2e", ClientSecret: "secret-e2e"})
	n, err := q.InsertIdentity(ctx, gen.InsertIdentityParams{
		UserID: user.ID, Provider: "oidc", Issuer: fake.Issuer(), Subject: "sub-e2e", CreatedAt: now,
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, n)

	provider := idp.Provider{ID: 1, Slug: "acme", DisplayName: "Acme ID", Issuer: fake.Issuer(),
		ClientID: "client-e2e", ClientSecret: "secret-e2e", Scopes: []string{"openid", "email", "profile"},
		TrustEmail: true, EmailDomains: []string{"example.test"}}
	idps := idp.NewRegistry(map[string]idp.Provider{"acme": provider}, map[string][]string{clientID: {"acme"}},
		idp.NewHTTPClient(true), true)

	aud := audit.NewService(q)
	t.Cleanup(func() { _ = aud.Close(context.Background()) })
	reg := service.NewRegistry(q)
	require.NoError(t, reg.Warmup(ctx))
	issuer := token.NewIssuerForTest()
	refreshSvc := token.NewRefreshService(sqldb, aud)
	cfg := config.Config{OIDCStateSecret: []byte("e2e-secret-32bytes-padded-here!!")}
	tmpl := template.Must(template.ParseGlob("../../templates/*.html"))

	loginH := &auth.LoginHandler{Registry: reg, Templates: tmpl, IDPs: idps}
	genericH := auth.NewGenericOIDCHandlers(cfg, sqldb, q, issuer, refreshSvc, reg, idps, aud)
	passwordH := auth.NewPasswordHandlers(q, issuer, refreshSvc, reg, aud, false)
	dispatchH := &auth.DispatchHandler{Registry: reg, Issuer: issuer, Queries: q, Audit: aud, Refresh: refreshSvc}

	r := chi.NewRouter()
	auth.UseGlobal(r, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.Get("/login", loginH.ServeLogin)
	r.Get("/idp/{slug}/login", genericH.HandleLogin)
	r.Get("/idp/{slug}/callback", genericH.HandleCallback)
	r.With(auth.CORSMiddleware(nil)).Post("/token", passwordH.Token)
	r.Get("/dispatch", dispatchH.ServeDispatch)
	r.Route("/.well-known", func(r chi.Router) {
		r.Get("/jwks.json", issuer.JWKSHandler)
	})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	browser := &http.Client{Jar: jar, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// get følger ett skritt og returnerer Location (cookies via jar).
	step := func(from string, wantStatus ...int) *url.URL {
		t.Helper()
		resp, err := browser.Get(from)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Contains(t, wantStatus, resp.StatusCode, "GET %s", from)
		raw := resp.Header.Get("Location")
		require.NotEmpty(t, raw, "3xx uten Location fra %s", from)
		base, _ := url.Parse(from)
		loc, err := base.Parse(raw)
		require.NoError(t, err)
		return loc
	}

	postToken := func(form url.Values) (int, map[string]any) {
		t.Helper()
		resp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		require.NoError(t, err)
		defer resp.Body.Close()
		var body map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		return resp.StatusCode, body
	}
	// login kjører hele nettleserdelen (steg 1-4) og returnerer koden og verifier.
	login := func() (code, verifier string) {
		t.Helper()
		// --- 1. Klienten starter authorization_code med PKCE ---
		vb := make([]byte, 32)
		_, _ = rand.Read(vb)
		verifier = base64.RawURLEncoding.EncodeToString(vb)
		authz := url.Values{
			"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
			"scope": {"openid email"}, "state": {"klient-state"}, "nonce": {"klient-nonce"},
			"code_challenge": {auth.S256Challenge(verifier)}, "code_challenge_method": {"S256"},
		}
		resp, err := browser.Get(srv.URL + "/login?" + authz.Encode())
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, "login-siden vises og oidc_authz-cookien settes")

		// --- 2. /idp/{slug}/login -> fake-IdP authorize -> /idp/{slug}/callback ---
		fake.Next(oidctest.Claims{Sub: "sub-e2e", Email: userEmail, EmailVerified: oidctest.EVTrue, Name: "Alice"}, oidctest.ModeOK)
		toIdP := step(srv.URL+"/idp/acme/login?service="+clientID, http.StatusFound)
		require.True(t, strings.HasPrefix(toIdP.String(), fake.URL()+"/authorize"), toIdP.String())
		back := step(toIdP.String(), http.StatusFound)
		require.Equal(t, "/idp/acme/callback", back.Path)

		// --- 3. Callback -> /dispatch (token + rt + service) ---
		disp := step(back.String(), http.StatusFound)
		require.Equal(t, "/dispatch", disp.Path)
		require.Equal(t, clientID, disp.Query().Get("service"))
		require.NotEmpty(t, disp.Query().Get("token"))

		// --- 4. /dispatch -> redirect til klientens redirect_uri med code og state ---
		final := step(disp.String(), http.StatusSeeOther)
		require.Equal(t, "app.e2e.test", final.Host)
		require.Equal(t, "/auth/callback", final.Path)
		require.Equal(t, "klient-state", final.Query().Get("state"))
		code = final.Query().Get("code")
		require.NotEmpty(t, code)
		return code, verifier
	}

	exchange := func(code, verifier string) (int, map[string]any) {
		t.Helper()
		return postToken(url.Values{
			"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
			"client_id": {clientID}, "code_verifier": {verifier},
		})
	}
	code, verifier := login()
	status, tok := exchange(code, verifier)
	require.Equal(t, http.StatusOK, status, "%v", tok)
	accessToken, _ := tok["access_token"].(string)
	rt1, _ := tok["refresh_token"].(string)
	require.NotEmpty(t, accessToken)
	require.NotEmpty(t, rt1)
	require.NotEmpty(t, tok["id_token"])

	// --- 6. Access-token mot JWKS: kid, RS256, aud ---
	jresp, err := http.Get(srv.URL + "/.well-known/jwks.json")
	require.NoError(t, err)
	defer jresp.Body.Close()
	var jwks jose.JSONWebKeySet
	require.NoError(t, json.NewDecoder(jresp.Body).Decode(&jwks))
	require.NotEmpty(t, jwks.Keys)

	jws, err := jose.ParseSigned(accessToken, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	hdr := jws.Signatures[0].Header
	require.Equal(t, string(jose.RS256), hdr.Algorithm)
	require.NotEmpty(t, hdr.KeyID)
	keys := jwks.Key(hdr.KeyID)
	require.Len(t, keys, 1, "kid %q må finnes i JWKS", hdr.KeyID)
	payload, err := jws.Verify(keys[0])
	require.NoError(t, err)
	var claims struct {
		Aud     any    `json:"aud"`
		Subject string `json:"sub"`
		Iss     string `json:"iss"`
		Exp     int64  `json:"exp"`
	}
	require.NoError(t, json.Unmarshal(payload, &claims))
	require.Contains(t, audList(claims.Aud), clientID)
	require.Equal(t, userEmail, claims.Subject)
	require.Equal(t, "https://test.example.com", claims.Iss)
	require.Greater(t, claims.Exp, time.Now().Unix())

	// --- 7. Refresh gir nytt refresh-token ---
	status, ref := postToken(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt1}})
	require.Equal(t, http.StatusOK, status, "%v", ref)
	rt2, _ := ref["refresh_token"].(string)
	require.NotEmpty(t, rt2)
	require.NotEqual(t, rt1, rt2)
	require.NotEmpty(t, ref["access_token"])

	// --- 8. Gjenbruk av gammelt refresh-token avvises og revokerer familien ---
	status, reuse := postToken(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt1}})
	require.Equal(t, http.StatusUnauthorized, status, "%v", reuse)
	require.Equal(t, "refresh_token_reused", reuse["error"])

	status, dead := postToken(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt2}})
	require.Equal(t, http.StatusUnauthorized, status, "det nye tokenet skal være revokert sammen med familien: %v", dead)

	// --- 9. Gjenbruk av authorization code: ny innlogging, ny kode ---
	// Egen innlogging, slik at familien fra rotasjonsdelen ikke maskerer
	// utfallet. Verifisert gjenbruk (samme klient, redirect_uri og verifier)
	// skal avvises og revokere familien koden ga.
	code2, verifier2 := login()
	status, tok2 := exchange(code2, verifier2)
	require.Equal(t, http.StatusOK, status, "%v", tok2)
	rtB, _ := tok2["refresh_token"].(string)
	require.NotEmpty(t, rtB)

	status, replay := exchange(code2, verifier2)
	require.GreaterOrEqual(t, status, 400, "%v", replay)
	require.Less(t, status, 500, "%v", replay)
	require.NotContains(t, replay, "access_token")

	status, revoked := postToken(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rtB}})
	require.Equal(t, http.StatusUnauthorized, status, "kode-gjenbruk skal revokere familien: %v", revoked)
}

func audList(v any) []string {
	switch a := v.(type) {
	case string:
		return []string{a}
	case []any:
		var out []string
		for _, e := range a {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
