package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

const (
	googleSubject = "112233445566778899001"
	msOid         = "9f8e7d6c-1111-2222-3333-444455556666"
	msTid         = "72f988bf-86f1-41af-91ab-2d7cd011db47"
)

// 011 F4: bruker-siden viser stabil id og koblede identiteter, bare lesing.
func TestUserEdit_ShowsPublicIDAndIdentities(t *testing.T) {
	e := setupDeactEnv(t)
	ctx := context.Background()
	u := e.mkUser(t, "ola@example.com")
	other := e.mkUser(t, "kari@example.com")
	last := "2026-10-10T08:00:00Z"
	mail := "ola@gmail.example"
	for _, p := range []gen.InsertIdentityParams{
		{UserID: u.ID, Provider: "google", Issuer: "https://accounts.google.com", Subject: googleSubject, Email: &mail, CreatedAt: "2026-10-01T10:00:00Z", LastUsedAt: &last},
		{UserID: u.ID, Provider: "microsoft", Issuer: "https://login.microsoftonline.com/" + msTid + "/v2.0", Subject: msOid, CreatedAt: "2026-10-02T10:00:00Z"},
		{UserID: other.ID, Provider: "google", Issuer: "https://accounts.google.com", Subject: "999888777666555444333", CreatedAt: "2026-10-01T10:00:00Z"},
	} {
		_, err := e.q.InsertIdentity(ctx, p)
		require.NoError(t, err)
	}

	h := NewUsersHandler(e.q, audit.NewService(e.q))
	r := chi.NewRouter()
	r.Get("/admin/users/{id}/edit", h.HandleEdit)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/users/"+strconv.FormatInt(u.ID, 10)+"/edit", nil))
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()

	assert.Contains(t, body, u.PublicID)
	assert.Contains(t, body, "google")
	assert.Contains(t, body, "microsoft")
	assert.Contains(t, body, msTid)
	assert.Contains(t, body, "ola@gmail.example")
	assert.Contains(t, body, "112233…")
	assert.Contains(t, body, "9f8e7d…")
	assert.Contains(t, body, "2026-10-10T08:00:00Z")
	// Aldri hele subject, og ikke andre brukeres identiteter.
	assert.NotContains(t, body, googleSubject)
	assert.NotContains(t, body, msOid)
	assert.NotContains(t, body, "999888")

	// Ukjent bruker gir 404.
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/users/99999/edit", nil))
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUserEdit_RequiresAdmin(t *testing.T) {
	e := setupDeactEnv(t)
	u := e.mkUser(t, "ola@example.com")
	issuer := token.NewIssuerForTest()
	h := NewUsersHandler(e.q, audit.NewService(e.q))
	r := chi.NewRouter()
	r.Use(AdminAuthMiddleware(issuer, adminDB(t, "konge@example.com", "konge")))
	r.Get("/admin/users/{id}/edit", h.HandleEdit)
	path := "/admin/users/" + strconv.FormatInt(u.ID, 10) + "/edit"

	// Uten admin-sesjon: redirect (HTML) eller 401 (JSON), aldri brukerdata.
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/admin/login", w.Header().Get("Location"))
	assert.NotContains(t, w.Body.String(), u.PublicID)

	req = httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Accept", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Med admin-sesjon: siden vises.
	req = httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(&http.Cookie{Name: "admin_token", Value: issuer.IssueAdminForTest("konge@example.com", "konge")})
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), u.PublicID)
}
