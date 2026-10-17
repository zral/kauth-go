package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zral/kauth-go/internal/token"
)

// Under nøkkelrotasjon skal admin-sesjoner signert med previous fortsatt slippe inn.
func TestAdminAuthMiddleware_TokenSignedWithPrevious_PassesThrough(t *testing.T) {
	rotated, old := token.NewRotatedIssuersForTest()
	mw := AdminAuthMiddleware(rotated, adminDB(t, "test@example.com", "konge"))
	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.AddCookie(&http.Cookie{Name: "admin_token", Value: old.IssueAdminForTest("test@example.com", "konge")})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rr.Code)
}
