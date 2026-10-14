package auth_test

import (
	"context"
	"database/sql"
	"encoding/base64"
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

// jwtClaim leser én claim fra nyttelasten uten å verifisere signaturen; testene
// her gjelder hva /token legger i tokenet, ikke signaturen.
func jwtClaim(t *testing.T, tok, name string) any {
	t.Helper()
	parts := strings.Split(tok, ".")
	require.Len(t, parts, 3)
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	return m[name]
}

type idFx struct {
	h     *auth.PasswordHandlers
	q     *gen.Queries
	sqldb *sql.DB
	ref   *token.RefreshService
	alice gen.User
	bob   gen.User
}

// newIDFx lager tjenesten «veivakt» med gitt sub_format og to brukere.
func newIDFx(t *testing.T, subFormat string) *idFx {
	t.Helper()
	ctx := context.Background()
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })
	sqldb.SetMaxOpenConns(1)
	now := time.Now().UTC().Format(time.RFC3339)
	require.NoError(t, q.CreateService(ctx, gen.CreateServiceParams{
		ID: "veivakt", DisplayName: "Veivakt", Domain: "veivakt.app",
		CallbackUrl: "https://veivakt.app/auth/callback",
		Theme:       "light", AccentColor: "#000", EmailFromName: "Veivakt",
		AutoRegister: 1, AuthMagicLink: 1, JwtCookieName: "auth_token", AccessTokenTtl: "PT15M",
		Active: 1, UpdatedAt: now,
	}))
	// CreateService tar ikke sub_format ennå (F4); satt direkte.
	_, err = sqldb.Exec(`UPDATE services SET sub_format = ? WHERE id = 'veivakt'`, subFormat)
	require.NoError(t, err)
	mk := func(email string) gen.User {
		u, err := q.CreateUser(ctx, gen.CreateUserParams{PublicID: token.MustNewPublicID(), Email: email, Roles: "user", Orgs: "o", CreatedAt: now})
		require.NoError(t, err)
		return u
	}
	alice, bob := mk("alice@example.com"), mk("bob@example.com")
	reg := service.NewRegistry(q)
	require.NoError(t, reg.Warmup(ctx))
	aud := audit.NewService(q)
	ref := token.NewRefreshService(sqldb, aud)
	h := auth.NewPasswordHandlers(q, token.NewIssuerForTest(), ref, reg, aud, true)
	return &idFx{h: h, q: q, sqldb: sqldb, ref: ref, alice: alice, bob: bob}
}

func (f *idFx) svc(t *testing.T) gen.Service {
	t.Helper()
	s, err := f.q.GetServiceByID(context.Background(), "veivakt")
	require.NoError(t, err)
	return s
}

func (f *idFx) refresh(t *testing.T, plain string) map[string]any {
	t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {plain}}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	f.h.Token(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return body
}

func TestRefreshGrant_SubFormatID_AfterRotation(t *testing.T) {
	f := newIDFx(t, "id")
	plain, err := f.ref.Issue(context.Background(), f.alice, f.svc(t), "", "")
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		body := f.refresh(t, plain)
		require.Equal(t, f.alice.PublicID, jwtClaim(t, body["access_token"].(string), "sub"), "rotasjon %d", i)
		require.Equal(t, f.alice.Email, jwtClaim(t, body["access_token"].(string), "email"))
		plain = body["refresh_token"].(string)
	}
}

func TestAuthorizationCode_SubFormatID(t *testing.T) {
	f := newIDFx(t, "id")
	verifier, challenge := pkcePair()
	insertCode := func(code string, userID *int64) {
		require.NoError(t, f.q.InsertAuthorizationCode(context.Background(), gen.InsertAuthorizationCodeParams{
			Code: token.HashOpaque(code), ServiceID: "veivakt", Email: f.alice.Email, UserID: userID,
			RedirectUri: "https://veivakt.app/auth/callback", CodeChallenge: challenge, CodeChallengeMethod: "S256",
			Scope: nullStr("openid"), CreatedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			ExpiresAt: time.Now().UTC().Add(time.Minute).Format("2006-01-02T15:04:05Z"),
		}))
	}
	exchange := func(code string) map[string]any {
		form := url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"redirect_uri": {"https://veivakt.app/auth/callback"}, "client_id": {"veivakt"}, "code_verifier": {verifier},
		}
		req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		f.h.Token(w, req)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var body map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		return body
	}

	insertCode("kode-med-id", &f.alice.ID)
	body := exchange("kode-med-id")
	require.Equal(t, f.alice.PublicID, jwtClaim(t, body["access_token"].(string), "sub"))
	require.Equal(t, f.alice.PublicID, jwtClaim(t, body["id_token"].(string), "sub"))
	// Refresh-raden fra innløsningen bærer user_id.
	var uid sql.NullInt64
	require.NoError(t, f.sqldb.QueryRow(`SELECT user_id FROM refresh_tokens WHERE token_hash = ?`, token.HashOpaque(body["refresh_token"].(string))).Scan(&uid))
	require.Equal(t, f.alice.ID, uid.Int64)

}

func nullStr(s string) *string { return &s }

// Rader uten user_id (M2) faller ikke tilbake til e-post: familien revokeres og
// refresh_user_inactive logges.
func TestRefreshGrant_LegacyRowWithoutUserID_Rejected(t *testing.T) {
	f := newIDFx(t, "email")
	plain, err := f.ref.Issue(context.Background(), f.alice, f.svc(t), "", "")
	require.NoError(t, err)
	_, err = f.sqldb.Exec(`UPDATE refresh_tokens SET user_id = NULL`)
	require.NoError(t, err)

	f.requireRefreshRejectedAndRevoked(t, plain)
}

// requireRefreshRejectedAndRevoked: 401, ingen levende rader i familien og audit.
func (f *idFx) requireRefreshRejectedAndRevoked(t *testing.T, plain string) {
	t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {plain}}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	f.h.Token(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	var live int
	require.NoError(t, f.sqldb.QueryRow(`SELECT COUNT(*) FROM refresh_tokens WHERE revoked = 0`).Scan(&live))
	require.Zero(t, live, "barnet fra rotasjonen skal være revokert")
	require.Eventually(t, func() bool {
		var n int
		_ = f.sqldb.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_type = 'refresh_user_inactive'`).Scan(&n)
		return n == 1
	}, 2*time.Second, 10*time.Millisecond)
}

// Kode uten user_id avvises på samme måte, og koden brennes ikke.
func TestAuthorizationCode_RowWithoutUserID_Rejected(t *testing.T) {
	f := newIDFx(t, "email")
	verifier, challenge := pkcePair()
	require.NoError(t, f.q.InsertAuthorizationCode(context.Background(), gen.InsertAuthorizationCodeParams{
		Code: token.HashOpaque("k"), ServiceID: "veivakt", Email: f.alice.Email,
		RedirectUri: "https://veivakt.app/auth/callback", CodeChallenge: challenge, CodeChallengeMethod: "S256",
		CreatedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		ExpiresAt: time.Now().UTC().Add(time.Minute).Format("2006-01-02T15:04:05Z"),
	}))
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {"k"},
		"redirect_uri": {"https://veivakt.app/auth/callback"}, "client_id": {"veivakt"}, "code_verifier": {verifier},
	}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	f.h.Token(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.JSONEq(t, `{"error":"invalid_grant"}`, w.Body.String())
	var used int
	require.NoError(t, f.sqldb.QueryRow(`SELECT used FROM authorization_codes`).Scan(&used))
	require.Zero(t, used)
}

// user_id vinner over e-post: en rad med user_id = alice og e-post = bob gir
// token for alice.
func TestRefreshGrant_UserIDWins(t *testing.T) {
	f := newIDFx(t, "email")
	plain, err := f.ref.Issue(context.Background(), f.alice, f.svc(t), "", "")
	require.NoError(t, err)
	_, err = f.sqldb.Exec(`UPDATE refresh_tokens SET email = ?`, f.bob.Email)
	require.NoError(t, err)

	body := f.refresh(t, plain)
	require.Equal(t, f.alice.Email, jwtClaim(t, body["access_token"].(string), "email"))
	require.Equal(t, f.alice.Email, jwtClaim(t, body["access_token"].(string), "sub"))
}

// Deaktivert bruker med user_id avvises selv om en annen aktiv bruker har
// e-posten på raden.
func TestRefreshGrant_UserIDInactive_DoesNotFallBackToEmail(t *testing.T) {
	f := newIDFx(t, "email")
	plain, err := f.ref.Issue(context.Background(), f.alice, f.svc(t), "", "")
	require.NoError(t, err)
	_, err = f.sqldb.Exec(`UPDATE refresh_tokens SET email = ?`, f.bob.Email)
	require.NoError(t, err)
	_, err = f.sqldb.Exec(`UPDATE users SET deactivated_at = '2026-01-01T00:00:00Z' WHERE id = ?`, f.alice.ID)
	require.NoError(t, err)

	f.requireRefreshRejectedAndRevoked(t, plain)
}

// ── /dispatch nivå 0 (PD12) ──

func signAccessSub(iss *token.Issuer, sub, aud string) string {
	return signAccessSubEmail(iss, sub, "sjafor@example.com", aud)
}

func signAccessSubEmail(iss *token.Issuer, sub, email, aud string) string {
	return iss.SignForTest(token.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "https://test.example.com", Subject: sub, ID: "jti-test",
			Audience:  jwt.ClaimStrings{aud},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
		Email: email, TokenUse: "access",
	})
}

func (f *audFixture) setSubFormat(t *testing.T, format string) {
	t.Helper()
	_, err := f.sqld.Exec(`UPDATE services SET sub_format = ? WHERE id = 'veivakt'`, format)
	require.NoError(t, err)
	require.NoError(t, f.h.Registry.Warmup(context.Background()))
}

func TestDispatchLevel0_SubjectMismatch(t *testing.T) {
	cases := []struct {
		name, format, sub, email string
		wantEvent                string // tom = ok
	}{
		{"email-tjeneste, sub er e-post", "email", "sjafor@example.com", "sjafor@example.com", ""},
		{"email-tjeneste, sub er annen", "email", "andre@example.com", "sjafor@example.com", "level=0 sub_format=email"},
		{"id-tjeneste, sub er e-post", "id", "sjafor@example.com", "sjafor@example.com", "level=0 reason=no_active_user"},
		{"id-tjeneste, sub er public_id", "id", "", "sjafor@example.com", ""},
		{"id-tjeneste, public_id men annen e-post", "id", "", "annen@example.com", "level=0 sub_format=id"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newOIDCAudFixture(t)
			f.setSubFormat(t, c.format)
			u, err := f.q.GetUserByEmail(context.Background(), "sjafor@example.com")
			require.NoError(t, err)
			sub := c.sub
			if sub == "" {
				sub = u.PublicID
			}
			w := f.dispatchOIDC(t, signAccessSubEmail(f.iss, sub, c.email, "veivakt"), "&service=veivakt")
			if c.wantEvent == "" {
				require.True(t, strings.HasPrefix(w.Header().Get("Location"), "https://veivakt.app/auth/callback?code="), w.Header().Get("Location"))
				require.Equal(t, 1, f.codeCount(t))
				require.Empty(t, f.eventsOf(t, "dispatch_subject_mismatch"))
				return
			}
			requireLoginNoCode(t, f, w)
			require.Equal(t, []string{c.wantEvent}, f.eventsOf(t, "dispatch_subject_mismatch"))
		})
	}
}

// Ukjent eller deaktivert bruker gir ingen kode.
func TestDispatchLevel0_UnknownOrInactiveUser(t *testing.T) {
	f := newOIDCAudFixture(t)
	_, err := f.sqld.Exec(`UPDATE users SET deactivated_at = '2026-01-01T00:00:00Z'`)
	require.NoError(t, err)
	w := f.dispatchOIDC(t, signAccessSub(f.iss, "sjafor@example.com", "veivakt"), "&service=veivakt")
	requireLoginNoCode(t, f, w)
	require.Equal(t, []string{"level=0 reason=no_active_user"}, f.eventsOf(t, "dispatch_subject_mismatch"))
}

func TestDispatchLevel0_StoresUserID(t *testing.T) {
	f := newOIDCAudFixture(t)
	// Mixed case i token-e-posten: oppslaget normaliserer, og raden får brukerens egen e-post.
	tok := f.iss.SignForTest(token.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "https://test.example.com", Subject: "sjafor@example.com", ID: "j",
			Audience:  jwt.ClaimStrings{"veivakt"},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
		Email: " Sjafor@Example.com", TokenUse: "access",
	})
	w := f.dispatchOIDC(t, tok, "&service=veivakt")
	require.True(t, strings.HasPrefix(w.Header().Get("Location"), "https://veivakt.app/auth/callback?code="), w.Header().Get("Location"))

	u, err := f.q.GetUserByEmail(context.Background(), "sjafor@example.com")
	require.NoError(t, err)
	var uid sql.NullInt64
	var email string
	require.NoError(t, f.sqld.QueryRow(`SELECT user_id, email FROM authorization_codes`).Scan(&uid, &email))
	require.True(t, uid.Valid)
	require.Equal(t, u.ID, uid.Int64)
	require.Equal(t, "sjafor@example.com", email)
}
