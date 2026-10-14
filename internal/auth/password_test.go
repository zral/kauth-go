package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/auth"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

func setupRefreshTest(t *testing.T) (*auth.PasswordHandlers, *token.RefreshService, gen.User, gen.Service) {
	t.Helper()
	ctx := context.Background()

	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })

	now := time.Now().UTC().Format(time.RFC3339)
	require.NoError(t, q.CreateService(ctx, gen.CreateServiceParams{
		ID: "vinkjeller", DisplayName: "Vinkjeller", Domain: "kjeller.test",
		CallbackUrl: "https://kjeller.test/auth/callback",
		Theme:       "light", AccentColor: "#000", EmailFromName: "Vinkjeller",
		AutoRegister: 1, AuthGoogle: 1, AuthMagicLink: 1,
		JwtCookieName: "auth_token", AccessTokenTtl: "PT15M",
		Active: 1, UpdatedAt: now,
	}))

	user, err := q.CreateUser(ctx, gen.CreateUserParams{
		Email: "alice@example.com", Roles: "user", Orgs: "vinkjeller", CreatedAt: now,
	})
	require.NoError(t, err)
	svc, err := q.GetServiceByID(ctx, "vinkjeller")
	require.NoError(t, err)

	iss := token.NewIssuerForTest()
	aud := audit.NewNoop()
	refSvc := token.NewRefreshService(sqldb, aud)
	reg := service.NewRegistry(q)
	require.NoError(t, reg.Warmup(ctx))

	h := auth.NewPasswordHandlers(q, iss, refSvc, reg, aud, true)
	return h, refSvc, user, svc
}

// Regresjon: POST /token må returnere `refresh_token` i JSON-respons.
// Uten denne kan klienten ikke lagre den roterte verdien og vil sende
// gammelt token ved neste refresh → reuse-deteksjon → bruker kastes ut.
func TestRefreshToken_ResponseIncludesRotatedRefreshToken(t *testing.T) {
	h, refSvc, user, svc := setupRefreshTest(t)
	plain, err := refSvc.Issue(context.Background(), user, svc, "127.0.0.1", "test")
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/token",
		strings.NewReader("grant_type=refresh_token&refresh_token="+plain))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.RefreshToken(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.NotEmpty(t, body["access_token"], "access_token må være i respons")
	require.NotEmpty(t, body["refresh_token"], "refresh_token må være i respons (regresjon: vinkjeller m.fl. leser denne)")
	require.NotEqual(t, plain, body["refresh_token"], "refresh_token må være rotert")
	require.Equal(t, "Bearer", body["token_type"])
}

// Regresjon: reuse-deteksjon returnerer `refresh_token_reused` med 401.
// Frontend (auth.js) skiller på denne for å vise sikkerhets-dialog.
func TestRefreshToken_ReuseReturnsRefreshTokenReused(t *testing.T) {
	h, refSvc, user, svc := setupRefreshTest(t)
	plain, err := refSvc.Issue(context.Background(), user, svc, "127.0.0.1", "test")
	require.NoError(t, err)

	// Første refresh — konsumerer tokenet.
	req1 := httptest.NewRequest("POST", "/token",
		strings.NewReader("grant_type=refresh_token&refresh_token="+plain))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w1 := httptest.NewRecorder()
	h.RefreshToken(w1, req1)
	require.Equal(t, http.StatusOK, w1.Code)

	// Andre refresh med samme (gamle) token — reuse.
	req2 := httptest.NewRequest("POST", "/token",
		strings.NewReader("grant_type=refresh_token&refresh_token="+plain))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	h.RefreshToken(w2, req2)

	require.Equal(t, http.StatusUnauthorized, w2.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &body))
	require.Equal(t, "refresh_token_reused", body["error"])
}

func TestRefreshToken_MissingTokenReturns400(t *testing.T) {
	h, _, _, _ := setupRefreshTest(t)
	req := httptest.NewRequest("POST", "/token", strings.NewReader("grant_type=refresh_token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.RefreshToken(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, "invalid_request", body["error"])
}

// Passord-login skal velge tjeneste med samme regel som sosial login: en
// undertjeneste på foreldrehosten vinner, en fremmed tenant gjør ikke.
func TestPasswordLogin_ResolvesLikeSocial(t *testing.T) {
	ctx := context.Background()
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })

	now := time.Now().UTC().Format(time.RFC3339)
	mk := func(id string, authHost *string, isDefault int64) {
		require.NoError(t, q.CreateService(ctx, gen.CreateServiceParams{
			ID: id, DisplayName: id, Domain: id + ".test", AuthHost: authHost,
			CallbackUrl: "https://" + id + ".test/cb", Theme: "light", AccentColor: "#000",
			EmailFromName: id, AuthPassword: 1, IsDefault: isDefault,
			JwtCookieName: "auth_token", AccessTokenTtl: "PT15M", Active: 1, UpdatedAt: now,
		}))
	}
	fh, xh := "auth.forelder.test", "auth.fremmed.test"
	mk("forelder", &fh, 1)
	mk("under", nil, 0)
	mk("fremmed", &xh, 0)

	hashBytes, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.MinCost)
	require.NoError(t, err)
	hash := string(hashBytes)
	_, err = q.CreateUser(ctx, gen.CreateUserParams{
		Email: "a@example.com", PasswordHash: &hash, Roles: "user", Orgs: "test", CreatedAt: now,
	})
	require.NoError(t, err)

	aud := audit.NewNoop()
	reg := service.NewRegistry(q)
	require.NoError(t, reg.Warmup(ctx))
	h := auth.NewPasswordHandlers(q, token.NewIssuerForTest(), token.NewRefreshService(sqldb, aud), reg, aud, true)

	servedAs := func(svcID string) string {
		form := url.Values{"email": {"a@example.com"}, "password": {"hunter2"}, "service_id": {svcID}}
		req := httptest.NewRequest(http.MethodPost, "/do-login", strings.NewReader(form.Encode()))
		req.Host = fh
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.DoLogin(w, req)
		require.Equal(t, http.StatusFound, w.Code)
		loc, err := url.Parse(w.Header().Get("Location"))
		require.NoError(t, err)
		return loc.Query().Get("service")
	}
	require.Equal(t, "under", servedAs("under"))
	require.Equal(t, "forelder", servedAs("fremmed"))
	require.Equal(t, "forelder", servedAs("finnes-ikke"))
	require.Equal(t, "forelder", servedAs(""))
}
