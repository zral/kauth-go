// Tester for 016 F4 — de to invitasjonsrutene gjennom ekte fetchmeta og AdminAuthMiddleware.
package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/fetchmeta"
	"github.com/zral/kauth-go/internal/token"
)

func TestInviteRoutes_RequireSameOriginAndAdmin(t *testing.T) {
	e := newInvEnv(t)
	adm := e.mkUser(t, "konge@example.com")
	_, err := e.sqldb.Exec("UPDATE users SET roles = 'konge' WHERE id = ?", adm.ID)
	require.NoError(t, err)
	issuer := token.NewIssuerForTest()
	cookie := issuer.IssueAdminForTest("konge@example.com", "konge")

	r := chi.NewRouter()
	r.Route("/admin", func(r chi.Router) {
		r.Use(fetchmeta.Middleware)
		r.Group(func(r chi.Router) {
			r.Use(AdminAuthMiddleware(issuer, e.q))
			r.Post("/users/{id}/link-invites", e.h.HandleInviteCreate)
			r.Post("/users/{id}/link-invites/{inviteID}/revoke", e.h.HandleInviteRevoke)
		})
	})
	do := func(path, site string, withCookie bool, vals url.Values) *httptest.ResponseRecorder {
		req := formPost(path, vals)
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Sec-Fetch-Site", site)
		if withCookie {
			req.AddCookie(&http.Cookie{Name: "admin_token", Value: cookie})
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		e.h.WaitForSends()
		return w
	}

	create := "/admin/users/" + id64(e.user.ID) + "/link-invites"
	vals := url.Values{"provider": {"acme"}, "service": {"svca"}}

	w := do(create, "cross-site", true, vals)
	assert.Equal(t, http.StatusForbidden, w.Code)
	w = do(create, "same-origin", false, vals)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/admin/login", w.Header().Get("Location"))
	assert.Empty(t, e.rows(t), "avviste kall oppretter ingen invitasjon")
	assert.Empty(t, e.mailer.all())

	w = do(create, "same-origin", true, vals)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	rows := e.rows(t)
	require.Len(t, rows, 1)

	revoke := create + "/" + id64(rows[0].ID) + "/revoke"
	w = do(revoke, "cross-site", true, nil)
	assert.Equal(t, http.StatusForbidden, w.Code)
	w = do(revoke, "same-origin", false, nil)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/admin/login", w.Header().Get("Location"))
	assert.Nil(t, e.rows(t)[0].UsedAt, "avviste kall trekker ikke tilbake")

	w = do(revoke, "same-origin", true, nil)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.NotNil(t, e.rows(t)[0].UsedAt)
}
