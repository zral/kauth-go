package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/auth"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

// Under nøkkelrotasjon skal tokens signert med previous godtas av /api/me og /dispatch.
func TestRotation_TokenSignedWithPreviousAccepted(t *testing.T) {
	rotated, old := token.NewRotatedIssuersForTest()
	user := gen.User{Email: "konge@example.com", Orgs: "lars", Roles: "konge"}
	svc := gen.Service{ID: "klarsyn", AccessTokenTtl: "PT15M"}
	at, err := old.IssueAccess(user, svc)
	require.NoError(t, err)

	t.Run("api/me", func(t *testing.T) {
		h := &auth.MeHandler{Issuer: rotated, CookieName: "auth_token"}
		req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
		req.AddCookie(&http.Cookie{Name: "auth_token", Value: at})
		w := httptest.NewRecorder()
		h.ServeMe(w, req)
		require.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("dispatch", func(t *testing.T) {
		h := &auth.DispatchHandler{
			Registry:     service.NewRegistryForTest(dispatchFixture()),
			Issuer:       rotated,
			Queries:      newDispatchQueries(t, "konge@example.com"),
			DefaultSvcID: "klarsyn",
		}
		req := httptest.NewRequest(http.MethodGet, "/dispatch?token="+at+"&service=klarsyn", nil)
		req.Host = "auth.klarsyn.net"
		w := httptest.NewRecorder()
		h.ServeDispatch(w, req)
		loc := w.Header().Get("Location")
		require.Equal(t, http.StatusSeeOther, w.Code, loc)
		require.True(t, hasPrefix(loc, "https://klarsyn.net/auth/callback"), loc)
	})
}
