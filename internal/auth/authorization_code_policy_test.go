package auth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/auth"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

func strPtrPolicy(s string) *string { return &s }

// Forsvar i dybden for angrepet Lars beskrev i PR-diskusjonen
// (github.com/zral/kauth-go/pull/1): ?service= på /dispatch er en
// URL-parameter angriperen selv styrer. Siden 010 bærer access-tokens aud,
// og /dispatch nivå 0 avviser et B-token for en A-kode (se
// TestDispatchLevel0_RejectsTokenForOtherService), så det opprinnelige
// angrepet stoppes der. Denne testen dekker laget bak: et token som har
// riktig aud for A, men der brukeren ikke (lenger) oppfyller A sin
// require_role, må likevel avvises idet koden løses inn. Policyen
// evalueres derfor på nytt i /token (checkPolicy).
func TestAuthorizationCodeGrant_RejectsUserWithoutRequiredRoleEvenWithValidCodeAndPKCE(t *testing.T) {
	ctx := context.Background()
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })

	now := time.Now().UTC().Format(time.RFC3339)
	// Tjeneste A: veivakt, krever rollen "partner" — det brukeren i dette
	// scenarioet IKKE har.
	require.NoError(t, q.CreateService(ctx, gen.CreateServiceParams{
		ID: "veivakt", DisplayName: "Veivakt", Domain: "veivakt.app",
		CallbackUrl: "https://veivakt.app/auth/callback",
		Theme:       "light", AccentColor: "#000", EmailFromName: "Veivakt",
		AuthGoogle: 1, RequireRole: strPtrPolicy("partner"),
		JwtCookieName: "auth_token", AccessTokenTtl: "PT15M",
		Active: 1, UpdatedAt: now,
	}))
	// Tjeneste B: minliste, ingen rollekrav — brukeren har lovlig tilgang.
	require.NoError(t, q.CreateService(ctx, gen.CreateServiceParams{
		ID: "minliste", DisplayName: "MinListe", Domain: "minliste.efugl.no",
		CallbackUrl: "https://minliste.efugl.no/auth/callback",
		Theme:       "light", AccentColor: "#000", EmailFromName: "MinListe",
		AuthGoogle: 1, JwtCookieName: "auth_token", AccessTokenTtl: "PT15M",
		Active: 1, UpdatedAt: now,
	}))
	user, err := q.CreateUser(ctx, gen.CreateUserParams{
		PublicID: token.MustNewPublicID(),
		Email:    "angriper@example.com", Roles: "user", Orgs: "drivstoffprisene", CreatedAt: now,
	})
	require.NoError(t, err)

	reg := service.NewRegistry(q)
	require.NoError(t, reg.Warmup(ctx))
	iss := token.NewIssuerForTest()
	aud := audit.NewNoop()
	refSvc := token.NewRefreshService(sqldb, aud)
	dispatchH := &auth.DispatchHandler{Registry: reg, Issuer: iss, Queries: q, DefaultSvcID: "minliste"}
	tokenH := auth.NewPasswordHandlers(q, iss, refSvc, reg, aud, true)

	svcA, err := q.GetServiceByID(ctx, "veivakt")
	require.NoError(t, err)

	// Steg 1: brukeren har et ferskt token med aud=veivakt (f.eks. utstedt
	// før require_role ble strammet inn), men mangler rollen nå.
	tokenForA, err := iss.IssueAccess(user, svcA)
	require.NoError(t, err)

	// Steg 2: en legitim oidc_authz-cookie for A ligger fra tidligere
	// (klikket "logg inn med kauth" i partner-app A).
	verifier := "angriperens-egen-lovlige-pkce-verifier-for-tjeneste-a-her"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	cookieWriter := httptest.NewRecorder()
	auth.SetOIDCAuthorizeCookie(cookieWriter, auth.OIDCAuthorizeRequest{
		ClientID: "veivakt", RedirectURI: "https://veivakt.app/auth/callback",
		State: "s1", CodeChallenge: challenge, CodeChallengeMethod: "S256",
	})

	// Steg 3: tokenet med aud=veivakt rett til /dispatch, uten å ha gått via
	// veivakt sin login-handler (der checkPolicy ville stoppet brukeren).
	dispatchReq := httptest.NewRequest(http.MethodGet, "/dispatch?token="+url.QueryEscape(tokenForA)+"&service=veivakt", nil)
	for _, c := range cookieWriter.Result().Cookies() {
		dispatchReq.AddCookie(c)
	}
	dispatchW := httptest.NewRecorder()
	dispatchH.ServeDispatch(dispatchW, dispatchReq)

	// Dispatch ser et gyldig, ferskt token for A og utsteder en kode. Policy
	// hører hjemme i /token, som er det neste laget.
	require.Equal(t, http.StatusSeeOther, dispatchW.Code)
	loc := dispatchW.Header().Get("Location")
	require.True(t, strings.HasPrefix(loc, "https://veivakt.app/auth/callback?"))
	redirectURL, err := url.Parse(loc)
	require.NoError(t, err)
	code := redirectURL.Query().Get("code")
	require.NotEmpty(t, code, "dispatch utsteder en kode her — det er selve poenget med testen")

	// Steg 4: angriperen løser inn koden hos veivakt med korrekt PKCE
	// verifier (de kontrollerer jo klienten sin egen side av flyten helt
	// fint). Dette MÅ likevel avvises, fordi de mangler "partner"-rollen
	// veivakt krever.
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://veivakt.app/auth/callback"}, "client_id": {"veivakt"},
		"code_verifier": {verifier},
	}
	tokenReq := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenW := httptest.NewRecorder()
	tokenH.Token(tokenW, tokenReq)

	require.Equal(t, http.StatusBadRequest, tokenW.Code, "må avvises: brukeren mangler veivakt sin påkrevde rolle, uansett hvor gyldig koden/PKCE er")
	var body map[string]string
	require.NoError(t, json.Unmarshal(tokenW.Body.Bytes(), &body))
	require.Equal(t, "invalid_grant", body["error"])
}
