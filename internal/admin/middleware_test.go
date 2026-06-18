package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zral/kauth-go/internal/token"
)

func TestAdminAuthMiddleware_NoCookie_HTML_Redirects(t *testing.T) {
	issuer := token.NewIssuerForTest()
	mw := AdminAuthMiddleware(issuer)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Equal(t, "/admin/login", rr.Header().Get("Location"))
}

func TestAdminAuthMiddleware_NoCookie_JSON_Returns401(t *testing.T) {
	issuer := token.NewIssuerForTest()
	mw := AdminAuthMiddleware(issuer)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Header().Get("Content-Type"), "application/json")
}

func TestAdminAuthMiddleware_ValidToken_PassesThrough(t *testing.T) {
	issuer := token.NewIssuerForTest()
	adminToken := issuer.IssueAdminForTest("test@example.com", "konge")
	mw := AdminAuthMiddleware(issuer)

	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.AddCookie(&http.Cookie{Name: "admin_token", Value: adminToken})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestAdminAuthMiddleware_WrongRole_Redirects(t *testing.T) {
	issuer := token.NewIssuerForTest()
	// Token med admin token_use men feil rolle
	adminToken := issuer.IssueAdminForTest("test@example.com", "vanlig")
	mw := AdminAuthMiddleware(issuer)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(&http.Cookie{Name: "admin_token", Value: adminToken})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
}
