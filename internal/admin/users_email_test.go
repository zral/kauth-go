package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/fetchmeta"
	"github.com/zral/kauth-go/internal/token"
)

func emailForm(email string) url.Values {
	return url.Values{"email": {email}, "confirm": {"1"}}
}

func (e *f3Env) userRow(t *testing.T, id int64) gen.User {
	t.Helper()
	u, err := e.q.GetUserByID(t.Context(), id)
	require.NoError(t, err)
	return u
}

func (e *f3Env) magicCount(t *testing.T) int {
	t.Helper()
	var n int
	require.NoError(t, e.sqldb.QueryRow("SELECT COUNT(*) FROM magic_tokens").Scan(&n))
	return n
}

func TestEmailChange_Success(t *testing.T) {
	e := newF3Env(t)
	u := e.mkUser(t, "ola@example.com")
	other := e.mkUser(t, "kari@example.com")
	t1, t2 := e.issueFamily(t, u), e.issueFamily(t, u)
	tOther := e.issueFamily(t, other)

	// Begge tidsformatene produksjonen skriver (admin og tjeneste) skal brennes.
	e.activeMagic(t, "h-old", "ola@example.com", "2006-01-02T15:04:05Z")
	e.activeMagic(t, "h-new", "ny@example.com", time.RFC3339)
	e.activeMagic(t, "h-third", "tredje@example.com", time.RFC3339)
	rows := e.magicCount(t)

	before := time.Now().UTC().Add(-time.Second)
	w := e.post(emailPath(u.ID), emailForm("  Ny@Example.COM "))
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.Equal(t, "/admin/users/"+id64(u.ID)+"/edit", w.Header().Get("Location"))

	got := e.userRow(t, u.ID)
	assert.Equal(t, "ny@example.com", got.Email, "normalisert")
	require.NotNil(t, got.EmailChangedAt)
	// Epoken skal kunne leses av dispatch og middleware: fast UTC-format.
	assert.Regexp(t, regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$`), *got.EmailChangedAt)
	parsed, err := token.ParseEpoch(*got.EmailChangedAt)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().UTC(), parsed, 5*time.Second)
	assert.False(t, parsed.Before(before.Truncate(time.Second)))
	epoch, err := token.EmailEpoch(got)
	require.NoError(t, err)
	assert.True(t, epoch.Equal(parsed), "EmailEpoch bruker email_changed_at")

	for _, tok := range []string{t1, t2} {
		rv, reason := e.rtState(t, tok)
		assert.EqualValues(t, 1, rv)
		assert.Equal(t, "email_changed", reason.String)
	}
	rv, _ := e.rtState(t, tOther)
	assert.EqualValues(t, 0, rv, "annen brukers familie står")

	assert.Equal(t, 1, e.magicUsed(t, "h-old"))
	assert.Equal(t, 1, e.magicUsed(t, "h-new"))
	assert.Equal(t, 0, e.magicUsed(t, "h-third"), "tredje adresse er urørt")
	assert.Equal(t, rows, e.magicCount(t), "kvoteradene står")

	email, d := e.auditRow(t, "user_email_changed")
	assert.Equal(t, "ny@example.com", email)
	for _, want := range []string{"id=" + id64(u.ID), `old="ola@example.com"`, "revoked=2", "burned=2", "actor=" + testActor} {
		assert.Contains(t, d, want)
	}
}

func TestEmailChange_Rejects(t *testing.T) {
	cases := []struct {
		name   string
		userID func(u int64) string
		form   url.Values
		status int
	}{
		{"ugyldig", nil, emailForm("ikke-en-epost"), http.StatusUnprocessableEntity},
		{"tom", nil, emailForm("  "), http.StatusUnprocessableEntity},
		{"uendret", nil, emailForm("ola@example.com"), http.StatusUnprocessableEntity},
		{"uendret med case og mellomrom", nil, emailForm("  OLA@Example.com "), http.StatusUnprocessableEntity},
		{"opptatt", nil, emailForm("kari@example.com"), http.StatusConflict},
		{"opptatt med annen case", nil, emailForm(" KARI@Example.com"), http.StatusConflict},
		{"mangler confirm", nil, url.Values{"email": {"ny@example.com"}}, http.StatusUnprocessableEntity},
		{"confirm med feil verdi", nil, url.Values{"email": {"ny@example.com"}, "confirm": {"0"}}, http.StatusUnprocessableEntity},
		{"ukjent bruker", func(int64) string { return "99999" }, emailForm("ny@example.com"), http.StatusNotFound},
		{"ikke-numerisk id", func(int64) string { return "abc" }, emailForm("ny@example.com"), http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newF3Env(t)
			u := e.mkUser(t, "ola@example.com")
			e.mkUser(t, "kari@example.com")
			e.addIdentity(t, u.ID, "google", "112233445566778899001")
			tok := e.issueFamily(t, u)
			e.activeMagic(t, "h-old", "ola@example.com", time.RFC3339)

			path := emailPath(u.ID)
			if tc.userID != nil {
				path = "/admin/users/" + tc.userID(u.ID) + "/email"
			}
			w := e.post(path, tc.form)
			assert.Equal(t, tc.status, w.Code)

			// Ingen skriving i noen av dem.
			got := e.userRow(t, u.ID)
			assert.Equal(t, "ola@example.com", got.Email)
			assert.Nil(t, got.EmailChangedAt)
			rv, _ := e.rtState(t, tok)
			assert.EqualValues(t, 0, rv)
			assert.Equal(t, 0, e.magicUsed(t, "h-old"))
			assert.Zero(t, e.auditCount(t, "user_email_changed"))

			if tc.status != http.StatusNotFound {
				body := w.Body.String()
				assert.Contains(t, body, "Koblede identiteter", "feilsiden viser identitetene")
				assert.Contains(t, body, "google")
				assert.Contains(t, body, `class="msg err"`)
			}
		})
	}
}

func TestEmailChange_InjectedFailure_NothingChanged(t *testing.T) {
	e := newF3Env(t)
	u := e.mkUser(t, "ola@example.com")
	tok := e.issueFamily(t, u)
	e.activeMagic(t, "h-old", "ola@example.com", time.RFC3339)
	_, err := e.sqldb.Exec(`CREATE TRIGGER fail_burn BEFORE UPDATE ON magic_tokens BEGIN SELECT RAISE(ABORT,'x'); END`)
	require.NoError(t, err)

	w := e.post(emailPath(u.ID), emailForm("ny@example.com"))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "databasefeil\n", w.Body.String())

	got := e.userRow(t, u.ID)
	assert.Equal(t, "ola@example.com", got.Email)
	assert.Nil(t, got.EmailChangedAt)
	rv, _ := e.rtState(t, tok)
	assert.EqualValues(t, 0, rv, "revokeringen er rullet tilbake")
	assert.Equal(t, 0, e.magicUsed(t, "h-old"))
	assert.Zero(t, e.auditCount(t, "user_email_changed"))
}

// K7: en samtidig opprettelse og en e-postendring til samme adresse. Unik-indeksen
// avgjør; taperen får en feilmelding, ikke en stille overskriving.
func TestEmailChange_RaceWithCreateUser(t *testing.T) {
	e := newF3FileEnv(t)
	u := e.mkUser(t, "ola@example.com")

	var wg sync.WaitGroup
	var createErr error
	var code int
	start := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, createErr = e.q.CreateUser(t.Context(), gen.CreateUserParams{
			PublicID: token.MustNewPublicID(), Email: "ny@example.com", Roles: "user", CreatedAt: "2026-10-01T10:00:00Z",
		})
	}()
	go func() {
		defer wg.Done()
		<-start
		code = e.post(emailPath(u.ID), emailForm("ny@example.com")).Code
	}()
	close(start)
	wg.Wait()

	var n int
	require.NoError(t, e.sqldb.QueryRow("SELECT COUNT(*) FROM users WHERE email = 'ny@example.com'").Scan(&n))
	assert.Equal(t, 1, n, "nøyaktig én rad har adressen")
	changeWon := code == http.StatusSeeOther
	createWon := createErr == nil
	assert.NotEqual(t, changeWon, createWon, "nøyaktig én vinner (endring=%d, create=%v)", code, createErr)
	if !changeWon {
		assert.Equal(t, http.StatusConflict, code, "taperen får 409, ikke 500")
	}
}

func TestEmailChange_DeactivatedUser_Allowed(t *testing.T) {
	e := newF3Env(t)
	u := e.mkUser(t, "ola@example.com")
	require.Equal(t, http.StatusSeeOther, e.deactivate(id64(u.ID)).Code)

	w := e.post(emailPath(u.ID), emailForm("ny@example.com"))
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "ny@example.com", e.userRow(t, u.ID).Email)
}

// K15: begge rutene ligger bak admin-middlewaren og samme-origin-sjekken, satt
// opp som i main.go.
func TestNewRoutes_RequireAdminAndSameOrigin(t *testing.T) {
	f := newF3Env(t)
	e := f.deactEnv
	admin := e.mkUser(t, "konge@example.com")
	_, err := e.sqldb.Exec("UPDATE users SET roles = 'konge' WHERE id = ?", admin.ID)
	require.NoError(t, err)
	victim := e.mkUser(t, "ola@example.com")
	gid := f.addIdentity(t, victim.ID, "google", "112233445566778899001")
	f.activeMagic(t, "h", "ola@example.com", time.RFC3339)

	issuer := token.NewIssuerForTest()
	cookie := issuer.IssueAdminForTest("konge@example.com", "konge")
	h := NewUsersHandler(e.q, e.sqldb, audit.NewService(e.q))
	r := chi.NewRouter()
	r.Route("/admin", func(r chi.Router) {
		r.Use(fetchmeta.Middleware)
		r.Group(func(r chi.Router) {
			r.Use(AdminAuthMiddleware(issuer, e.q))
			r.Post("/users/{id}/email", h.HandleEmailChange)
			r.Post("/users/{id}/identities/{identityID}/unlink", h.HandleUnlink)
		})
	})

	paths := map[string]url.Values{
		emailPath(victim.ID):       emailForm("ny@example.com"),
		unlinkPath(victim.ID, gid): nil,
	}
	for path, vals := range paths {
		do := func(site string, withCookie bool) *httptest.ResponseRecorder {
			req := formPost(path, vals)
			req.Header.Set("Accept", "text/html")
			req.Header.Set("Sec-Fetch-Site", site)
			if withCookie {
				req.AddCookie(&http.Cookie{Name: "admin_token", Value: cookie})
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			return w
		}
		w := do("same-origin", false)
		assert.Equal(t, http.StatusSeeOther, w.Code, path)
		assert.Equal(t, "/admin/login", w.Header().Get("Location"), path)

		w = do("cross-site", true)
		assert.Equal(t, http.StatusForbidden, w.Code, path)
		w = do("cross-site", false)
		assert.Equal(t, http.StatusForbidden, w.Code, path)

		// Ingen av forsøkene skrev noe.
		assert.Equal(t, "ola@example.com", e.userRowFor(t, victim.ID).Email, path)
		var n int
		require.NoError(t, e.sqldb.QueryRow("SELECT COUNT(*) FROM user_identities WHERE id = ?", gid).Scan(&n))
		assert.Equal(t, 1, n, path)
	}

	// Kontroll: med admin-cookie og samme origin går kallet gjennom.
	req := formPost(emailPath(victim.ID), emailForm("ny@example.com"))
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(&http.Cookie{Name: "admin_token", Value: cookie})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "ny@example.com", e.userRowFor(t, victim.ID).Email)
	assert.True(t, strings.HasPrefix(w.Header().Get("Location"), "/admin/users/"))
}

func (e *deactEnv) userRowFor(t *testing.T, id int64) gen.User {
	t.Helper()
	u, err := e.q.GetUserByID(t.Context(), id)
	require.NoError(t, err)
	return u
}

// K16: siden viser bundet-markøren og én frakoblingsknapp per identitet, og
// e-postskjemaet med advarsel og avkrysning.
func TestUserEdit_ShowsBoundAndUnlinkButtons(t *testing.T) {
	e := newF3Env(t)
	u := e.mkUser(t, "konge@example.com")
	g := e.addIdentity(t, u.ID, "google", "112233445566778899001")
	m := e.addIdentity(t, u.ID, "microsoft", msOid)
	_, err := e.sqldb.Exec("UPDATE users SET admin_bound_at = '2026-10-05T12:00:00Z' WHERE id = ?", u.ID)
	require.NoError(t, err)
	_, err = e.sqldb.Exec("UPDATE user_identities SET admin_ok = 1 WHERE id = ?", g)
	require.NoError(t, err)

	body := e.get("/admin/users/" + id64(u.ID) + "/edit").Body.String()
	assert.Contains(t, body, "Admin-Google er bundet <strong>2026-10-05T12:00:00Z</strong>")
	assert.NotContains(t, body, "driftsprosedyren", "admin_ok-identitet finnes")
	for _, id := range []int64{g, m} {
		assert.Contains(t, body, `action="/admin/users/`+id64(u.ID)+`/identities/`+id64(id)+`/unlink"`)
	}
	assert.Equal(t, 2, strings.Count(body, "/unlink\""))
	assert.Contains(t, body, `action="/admin/users/`+id64(u.ID)+`/email"`)
	assert.Contains(t, body, `for="new_email"`)
	assert.Contains(t, body, `name="confirm"`)
	assert.Contains(t, body, "sub_format=email")
	assert.Contains(t, body, "bruker,konge")
	assert.NotContains(t, body, "kong\u00bb")

	// Ubundet bruker: ingen markør.
	u2 := e.mkUser(t, "ola@example.com")
	body = e.get("/admin/users/" + id64(u2.ID) + "/edit").Body.String()
	assert.NotContains(t, body, "Admin-Google er bundet")
}

// PD8/PD9: feiler audit etter lagring, står endringen, og redirecten går til
// listesiden som viser varselet.
func TestF3Writes_AuditFailureRedirectsToListWithWarn(t *testing.T) {
	e := setupDeactEnv(t)
	f := &f3Env{deactEnv: e}
	h := NewUsersHandler(e.q, e.sqldb, failingAudit{})
	r := chi.NewRouter()
	r.Use(withActor)
	r.Get("/admin/users", h.HandleList)
	r.Post("/admin/users/{id}/email", h.HandleEmailChange)
	r.Post("/admin/users/{id}/identities/{identityID}/unlink", h.HandleUnlink)

	u := e.mkUser(t, "ola@example.com")
	gid := f.addIdentity(t, u.ID, "google", "112233445566778899001")
	do := func(path string, vals url.Values) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, formPost(path, vals))
		return w
	}

	w := do(emailPath(u.ID), emailForm("ny@example.com"))
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/admin/users?warn=audit", w.Header().Get("Location"))
	assert.Equal(t, "ny@example.com", e.userRowFor(t, u.ID).Email, "endringen står")

	w = do(unlinkPath(u.ID, gid), nil)
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/admin/users?warn=audit", w.Header().Get("Location"))
	var n int
	require.NoError(t, e.sqldb.QueryRow("SELECT COUNT(*) FROM user_identities WHERE id = ?", gid).Scan(&n))
	assert.Zero(t, n, "frakoblingen står")

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/users?warn=audit", nil))
	assert.Contains(t, rec.Body.String(), "Lagret, men ikke auditert.")
}

// Et utløpt token for gammel adresse røres ikke; bare aktive brennes.
func TestEmailChange_ExpiredMagicTokenUntouched(t *testing.T) {
	e := newF3Env(t)
	u := e.mkUser(t, "ola@example.com")
	_, err := e.sqldb.Exec(`INSERT INTO magic_tokens (token, email, purpose, created_at, expires_at, used)
		VALUES ('h-exp', 'ola@example.com', 'admin', '2020-01-01T00:00:00Z', '2020-01-01T00:15:00Z', 0)`)
	require.NoError(t, err)
	require.Equal(t, http.StatusSeeOther, e.post(emailPath(u.ID), emailForm("ny@example.com")).Code)
	assert.Equal(t, 0, e.magicUsed(t, "h-exp"))
}

// Admin som endrer sin egen adresse mister sesjonen: tokenet bærer den gamle
// adressen, som ikke lenger finnes. Epokesjekken (PD6) dekkes av middleware-testene.
func TestEmailChange_OwnAddress_InvalidatesAdminToken(t *testing.T) {
	e := newF3Env(t)
	admin := e.mkUser(t, "konge@example.com")
	_, err := e.sqldb.Exec("UPDATE users SET roles = 'konge' WHERE id = ?", admin.ID)
	require.NoError(t, err)
	issuer := token.NewIssuerForTest()
	// iat to sekunder før endringen, slik at sekundoppløsningen ikke maskerer testen.
	tok := adminTokenAt(issuer, "konge@example.com", time.Now().Add(-2*time.Second))
	code, _, called := serveWith(t, issuer, e.q, tok)
	require.Equal(t, http.StatusOK, code, "tokenet virker før endringen")
	require.True(t, called)

	require.Equal(t, http.StatusSeeOther, e.post(emailPath(admin.ID), emailForm("konge2@example.com")).Code)

	// Tokenet bærer den gamle adressen; oppslaget finner ikke lenger brukeren.
	code, loc, called := serveWith(t, issuer, e.q, tok)
	assert.Equal(t, http.StatusSeeOther, code)
	assert.Equal(t, "/admin/login", loc)
	assert.False(t, called)
}
