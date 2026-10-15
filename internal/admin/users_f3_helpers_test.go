package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

// f3Env samler det frakobling og e-postendring trenger: handler med aktør i
// konteksten, og hjelpere for å så rader og lese tilstand.
type f3Env struct {
	*deactEnv
	mux http.Handler
}

func newF3Env(t *testing.T) *f3Env {
	t.Helper()
	e := setupDeactEnv(t)
	return &f3Env{deactEnv: e, mux: f3Router(NewUsersHandler(e.q, e.sqldb, audit.NewService(e.q)))}
}

// newF3FileEnv bruker en fil-DB med flere tilkoblinger, slik at to
// forespørsler faktisk konkurrerer om skrivelåsen.
func newF3FileEnv(t *testing.T) *f3Env {
	t.Helper()
	// deactEnv.mux settes ikke her, så deactivate() kan ikke brukes på fil-env-en.
	setupDeactEnv(t) // chdir til rot; minne-DB-en brukes ikke videre
	sqldb, q, err := db.Open(filepath.Join(t.TempDir(), "f3.db"))
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })
	for _, id := range []string{"svca", "svcb"} {
		require.NoError(t, q.CreateService(context.Background(), gen.CreateServiceParams{
			ID: id, DisplayName: id, Domain: id + ".test", CallbackUrl: "https://" + id + ".test/cb",
			Theme: "light", AccentColor: "#000", EmailFromName: id, JwtCookieName: id + "_tok",
			AccessTokenTtl: "PT30M", Active: 1, UpdatedAt: "2026-10-01T10:00:00Z",
		}))
	}
	aud := audit.NewService(q)
	e := &deactEnv{sqldb: sqldb, q: q, refSv: token.NewRefreshService(sqldb, aud)}
	return &f3Env{deactEnv: e, mux: f3Router(NewUsersHandler(q, sqldb, aud))}
}

func f3Router(h *UsersHandler) http.Handler {
	r := chi.NewRouter()
	r.Use(withActor)
	r.Get("/admin/users/{id}/edit", h.HandleEdit)
	r.Post("/admin/users/{id}/email", h.HandleEmailChange)
	r.Post("/admin/users/{id}/identities/{identityID}/unlink", h.HandleUnlink)
	return r
}

func (e *f3Env) post(path string, vals url.Values) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, formPost(path, vals))
	return w
}

func (e *f3Env) get(path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

func (e *f3Env) addIdentity(t *testing.T, userID int64, provider, subject string) int64 {
	t.Helper()
	issuer := "https://accounts.google.com"
	if provider == "microsoft" {
		issuer = "https://login.microsoftonline.com/" + msTid + "/v2.0"
	}
	// InsertIdentity returnerer antall rader, ikke id-en.
	_, err := e.q.InsertIdentity(context.Background(), gen.InsertIdentityParams{
		UserID: userID, Provider: provider, Issuer: issuer, Subject: subject, CreatedAt: "2026-10-01T10:00:00Z",
	})
	require.NoError(t, err)
	var id int64
	require.NoError(t, e.sqldb.QueryRow("SELECT id FROM user_identities WHERE issuer = ? AND subject = ?", issuer, subject).Scan(&id))
	return id
}

func (e *f3Env) issueFamily(t *testing.T, u gen.User) string {
	t.Helper()
	tok, err := e.refSv.Issue(context.Background(), u, gen.Service{ID: "svca"}, "", "")
	require.NoError(t, err)
	return tok
}

func (e *f3Env) auditRow(t *testing.T, typ string) (email, details string) {
	t.Helper()
	// LogSync: raden finnes når handleren har returnert.
	require.NoError(t, e.sqldb.QueryRow(
		`SELECT COALESCE(email,''), COALESCE(details,'') FROM audit_events WHERE event_type = ? ORDER BY id DESC LIMIT 1`, typ).
		Scan(&email, &details), typ)
	return
}

func (e *f3Env) auditCount(t *testing.T, typ string) int {
	t.Helper()
	var n int
	require.NoError(t, e.sqldb.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_type = ?`, typ).Scan(&n))
	return n
}

func id64(id int64) string { return strconv.FormatInt(id, 10) }

func unlinkPath(userID, identityID int64) string {
	return "/admin/users/" + id64(userID) + "/identities/" + id64(identityID) + "/unlink"
}

func emailPath(userID int64) string { return "/admin/users/" + id64(userID) + "/email" }

// activeMagic legger inn et ubrukt magic-token slik produksjonskoden gjør:
// created_at/expires_at i "2006-01-02T15:04:05Z" (UTC), via samme query.
func (e *f3Env) activeMagic(t *testing.T, hash, email, layout string) {
	t.Helper()
	now := time.Now().UTC()
	n, err := e.q.InsertMagicTokenLimited(context.Background(), gen.InsertMagicTokenLimitedParams{
		TokenHash: hash, Email: email, Purpose: "admin",
		CreatedAt:   now.Format(layout),
		ExpiresAt:   now.Add(15 * time.Minute).Format(layout),
		WindowStart: now.Add(-15 * time.Minute).Format(layout),
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
}

func (e *f3Env) magicUsed(t *testing.T, hash string) int {
	t.Helper()
	var used int
	require.NoError(t, e.sqldb.QueryRow(`SELECT used FROM magic_tokens WHERE token = ?`, hash).Scan(&used))
	return used
}
