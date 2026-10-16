package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/idp"
	"github.com/zral/kauth-go/internal/token"
)

type sentInvite struct{ to, fromName, link, provider, locale, fromAddress string }

type fakeInviteMailer struct {
	mu   sync.Mutex
	sent []sentInvite
}

func (f *fakeInviteMailer) SendLinkInvite(to, fromName, linkURL, providerName, locale, fromAddress string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, sentInvite{to, fromName, linkURL, providerName, locale, fromAddress})
	return nil
}

func (f *fakeInviteMailer) all() []sentInvite {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sentInvite(nil), f.sent...)
}

type invEnv struct {
	*f3Env
	h      *UsersHandler
	mailer *fakeInviteMailer
	user   gen.User
}

// newInvEnv: acme (1) er lastet og tilordnet svca og svcb, skjult (2) er avvist
// men tilordnet svca, annen (3) er lastet men ikke tilordnet, og svcc er
// deaktivert med acme tilordnet.
func newInvEnv(t *testing.T) *invEnv {
	t.Helper()
	f := newF3Env(t)
	for _, q := range []string{
		`INSERT INTO identity_providers (id,slug,display_name,issuer,client_id,client_secret_env) VALUES (1,'acme','Acme','https://idp.acme.example','c1','KAUTH_IDP_ACME')`,
		`INSERT INTO identity_providers (id,slug,display_name,issuer,client_id) VALUES (2,'skjult','Skjult','https://skjult.example','c2')`,
		`INSERT INTO identity_providers (id,slug,display_name,issuer,client_id) VALUES (3,'annen','Annen','https://annen.example','c3')`,
		`INSERT INTO services (id,display_name,domain,callback_url,theme,accent_color,email_from_name,jwt_cookie_name,access_token_ttl,active,updated_at)
		 VALUES ('svcc','svcc','svcc.test','https://svcc.test/cb','light','#000','svcc','svcc_tok','PT30M',0,'2026-10-01T10:00:00Z')`,
		`UPDATE services SET auth_host = 'auth.svca.test' WHERE id = 'svca'`,
		`INSERT INTO service_identity_providers (service_id,provider_id,position) VALUES ('svca',1,1)`,
		`INSERT INTO service_identity_providers (service_id,provider_id,position) VALUES ('svca',2,2)`,
		`INSERT INTO service_identity_providers (service_id,provider_id,position) VALUES ('svcb',1,1)`,
		`INSERT INTO service_identity_providers (service_id,provider_id,position) VALUES ('svcc',1,1)`,
	} {
		_, err := f.sqldb.Exec(q)
		require.NoError(t, err, q)
	}
	provs, by, sts, err := idp.Load(context.Background(), f.q, idp.Options{
		Allowlist: []string{"https://idp.acme.example", "https://annen.example"},
		Getenv: func(k string) string {
			if k == "KAUTH_IDP_ACME" {
				return "x"
			}
			return ""
		},
	})
	require.NoError(t, err)
	idps := idp.NewRegistryWithStatuses(provs, by, sts, nil, false)
	_, loaded := idps.Get("skjult")
	require.False(t, loaded)

	mailer := &fakeInviteMailer{}
	h := NewUsersHandler(f.q, f.sqldb, audit.NewService(f.q)).WithInvites(idps, mailer, "https://base.test")
	r := chi.NewRouter()
	r.Use(withActor)
	r.Get("/admin/users/{id}/edit", h.HandleEdit)
	r.Post("/admin/users/{id}/email", h.HandleEmailChange)
	r.Post("/admin/users/{id}/link-invites", h.HandleInviteCreate)
	r.Post("/admin/users/{id}/link-invites/{inviteID}/revoke", h.HandleInviteRevoke)
	f.mux = r
	return &invEnv{f3Env: f, h: h, mailer: mailer, user: f.mkUser(t, "Bruker@Firma.no")}
}

func (e *invEnv) invite(userID int64, slug, svc string) *httptest.ResponseRecorder {
	w := e.post("/admin/users/"+id64(userID)+"/link-invites", url.Values{"provider": {slug}, "service": {svc}})
	e.h.WaitForSends()
	return w
}

func (e *invEnv) rows(t *testing.T) []gen.IdentityLinkInvite {
	t.Helper()
	rs, err := e.sqldb.Query(`SELECT id, token_hash, user_id, provider_id, service_id, email, created_by, created_at, expires_at, used_at FROM identity_link_invites ORDER BY id`)
	require.NoError(t, err)
	defer rs.Close()
	var out []gen.IdentityLinkInvite
	for rs.Next() {
		var i gen.IdentityLinkInvite
		require.NoError(t, rs.Scan(&i.ID, &i.TokenHash, &i.UserID, &i.ProviderID, &i.ServiceID, &i.Email, &i.CreatedBy, &i.CreatedAt, &i.ExpiresAt, &i.UsedAt))
		out = append(out, i)
	}
	return out
}

func tokenOf(t *testing.T, link string) string {
	t.Helper()
	_, tok, ok := strings.Cut(link, "/link/")
	require.True(t, ok, link)
	return tok
}

func TestInviteCreate_StoresHashSendsMailAndAudits(t *testing.T) {
	e := newInvEnv(t)
	w := e.invite(e.user.ID, "acme", "svca")
	require.Equal(t, http.StatusSeeOther, w.Code)

	sent := e.mailer.all()
	require.Len(t, sent, 1)
	assert.Equal(t, "bruker@firma.no", sent[0].to)
	assert.True(t, strings.HasPrefix(sent[0].link, "https://auth.svca.test/link/"), sent[0].link)
	assert.Equal(t, "Acme", sent[0].provider)
	assert.Equal(t, "svca", sent[0].fromName)
	plain := tokenOf(t, sent[0].link)
	assert.Len(t, plain, 43)

	rows := e.rows(t)
	require.Len(t, rows, 1)
	r := rows[0]
	assert.NotEqual(t, plain, r.TokenHash)
	assert.Equal(t, token.HashOpaque(plain), r.TokenHash)
	assert.Len(t, r.TokenHash, 64)
	assert.Equal(t, e.user.ID, r.UserID)
	assert.EqualValues(t, 1, r.ProviderID)
	assert.Equal(t, "svca", r.ServiceID)
	assert.Equal(t, "bruker@firma.no", r.Email)
	assert.Equal(t, testActor, r.CreatedBy)
	assert.Nil(t, r.UsedAt)
	created, err := time.Parse(token.LinkInviteTimeFormat, r.CreatedAt)
	require.NoError(t, err)
	exp, err := time.Parse(token.LinkInviteTimeFormat, r.ExpiresAt)
	require.NoError(t, err)
	assert.Equal(t, 24*time.Hour, exp.Sub(created))

	_, details := e.auditRow(t, "identity_link_invited")
	assert.Contains(t, details, "id="+id64(e.user.ID)+" invite="+id64(r.ID)+" provider=acme service=svca")
	assert.Contains(t, details, "actor="+testActor)
	assert.NotContains(t, details, plain)
	assert.NotContains(t, details, r.TokenHash)

	// Verken respons, redirect eller brukersiden lekker tokenet.
	assert.NotContains(t, w.Body.String()+w.Header().Get("Location"), plain)
	page := e.get("/admin/users/" + id64(e.user.ID) + "/edit?invite=sent")
	require.Equal(t, http.StatusOK, page.Code)
	body := page.Body.String()
	assert.NotContains(t, body, plain)
	assert.NotContains(t, body, r.TokenHash)
	assert.NotContains(t, body, "/link/")
	assert.Contains(t, body, "Invitasjon sendt til")
	assert.Contains(t, body, "Trekk tilbake")
}

func TestInviteCreate_FallsBackToBaseURL(t *testing.T) {
	e := newInvEnv(t)
	require.Equal(t, http.StatusSeeOther, e.invite(e.user.ID, "acme", "svcb").Code)
	sent := e.mailer.all()
	require.Len(t, sent, 1)
	assert.True(t, strings.HasPrefix(sent[0].link, "https://base.test/link/"), sent[0].link)
}

func TestInviteCreate_Rejections(t *testing.T) {
	e := newInvEnv(t)
	inactive := e.mkUser(t, "inaktiv@firma.no")
	_, err := e.sqldb.Exec(`UPDATE users SET deactivated_at = '2026-10-01T10:00:00Z' WHERE id = ?`, inactive.ID)
	require.NoError(t, err)
	noMail := e.mkUser(t, "blank@firma.no")
	_, err = e.sqldb.Exec(`UPDATE users SET email = '' WHERE id = ?`, noMail.ID)
	require.NoError(t, err)

	cases := []struct {
		name      string
		user      int64
		slug, svc string
	}{
		{"deaktivert bruker", inactive.ID, "acme", "svca"},
		{"bruker uten e-post", noMail.ID, "acme", "svca"},
		{"ikke-lastet leverandør", e.user.ID, "skjult", "svca"},
		{"ukjent leverandør", e.user.ID, "finnes-ikke", "svca"},
		{"ikke tilordnet tjenesten", e.user.ID, "annen", "svca"},
		{"leverandør tilordnet bare andre tjenester", e.user.ID, "acme", "finnes-ikke"},
		{"inaktiv tjeneste", e.user.ID, "acme", "svcc"},
		{"tomme felt", e.user.ID, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := e.invite(c.user, c.slug, c.svc)
			assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
		})
	}
	assert.Empty(t, e.rows(t))
	assert.Empty(t, e.mailer.all())
	assert.Equal(t, 0, e.auditCount(t, "identity_link_invited"))

	assert.Equal(t, http.StatusNotFound, e.invite(99999, "acme", "svca").Code)
}

func TestInviteCreate_NewBurnsPreviousForSameProvider(t *testing.T) {
	e := newInvEnv(t)
	require.Equal(t, http.StatusSeeOther, e.invite(e.user.ID, "acme", "svca").Code)
	require.Equal(t, http.StatusSeeOther, e.invite(e.user.ID, "acme", "svcb").Code)
	rows := e.rows(t)
	require.Len(t, rows, 2)
	assert.NotNil(t, rows[0].UsedAt, "forrige skal være brent")
	assert.Nil(t, rows[1].UsedAt)

	// Annen bruker påvirkes ikke.
	other := e.mkUser(t, "annen@firma.no")
	require.Equal(t, http.StatusSeeOther, e.invite(other.ID, "acme", "svca").Code)
	require.Equal(t, http.StatusSeeOther, e.invite(e.user.ID, "acme", "svca").Code)
	for _, r := range e.rows(t) {
		if r.UserID == other.ID {
			assert.Nil(t, r.UsedAt)
		}
	}
}

func TestInviteCreate_SixthInHourRejectedAndOldStaysValid(t *testing.T) {
	e := newInvEnv(t)
	for i := 0; i < 5; i++ {
		require.Equal(t, http.StatusSeeOther, e.invite(e.user.ID, "acme", "svca").Code, "invitasjon %d", i+1)
	}
	require.Len(t, e.mailer.all(), 5)

	w := e.invite(e.user.ID, "acme", "svca")
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Contains(t, w.Body.String(), "For mange invitasjoner siste time")
	assert.Len(t, e.mailer.all(), 5, "ingen e-post for avvist invitasjon")

	rows := e.rows(t)
	require.Len(t, rows, 5)
	assert.Nil(t, rows[4].UsedAt, "rollback: den forrige invitasjonen skal fortsatt gjelde")
	for _, r := range rows[:4] {
		assert.NotNil(t, r.UsedAt)
	}
	assert.Equal(t, 5, e.auditCount(t, "identity_link_invited"))
}

func TestInviteCreate_RateWindowExpires(t *testing.T) {
	e := newInvEnv(t)
	for i := 0; i < 5; i++ {
		require.Equal(t, http.StatusSeeOther, e.invite(e.user.ID, "acme", "svca").Code)
	}
	e.h.inv.now = func() time.Time { return time.Now().Add(61 * time.Minute) }
	assert.Equal(t, http.StatusSeeOther, e.invite(e.user.ID, "acme", "svca").Code)
}

func TestInviteRevoke(t *testing.T) {
	e := newInvEnv(t)
	other := e.mkUser(t, "annen@firma.no")
	require.Equal(t, http.StatusSeeOther, e.invite(e.user.ID, "acme", "svca").Code)
	inv := e.rows(t)[0]
	path := func(u int64) string {
		return "/admin/users/" + id64(u) + "/link-invites/" + id64(inv.ID) + "/revoke"
	}

	assert.Equal(t, http.StatusNotFound, e.post(path(other.ID), nil).Code)
	assert.Nil(t, e.rows(t)[0].UsedAt, "feil bruker skal ikke trekke tilbake")
	assert.Equal(t, 0, e.auditCount(t, "identity_link_invite_revoked"))

	w := e.post(path(e.user.ID), nil)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.NotNil(t, e.rows(t)[0].UsedAt)
	_, details := e.auditRow(t, "identity_link_invite_revoked")
	assert.Contains(t, details, "id="+id64(e.user.ID)+" invite="+id64(inv.ID))
	assert.Contains(t, details, "actor="+testActor)

	assert.Equal(t, http.StatusNotFound, e.post(path(e.user.ID), nil).Code, "allerede tilbakekalt")
	assert.Equal(t, http.StatusNotFound, e.post("/admin/users/"+id64(e.user.ID)+"/link-invites/999/revoke", nil).Code)
}

func TestInvite_EmailChangeBurnsInvites(t *testing.T) {
	e := newInvEnv(t)
	require.Equal(t, http.StatusSeeOther, e.invite(e.user.ID, "acme", "svca").Code)
	w := e.post(emailPath(e.user.ID), url.Values{"email": {"ny@firma.no"}, "confirm": {"1"}})
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.NotNil(t, e.rows(t)[0].UsedAt)
}

func TestInvite_UserPageListsActiveAndHidesFormForDeactivated(t *testing.T) {
	e := newInvEnv(t)
	require.Equal(t, http.StatusSeeOther, e.invite(e.user.ID, "acme", "svca").Code)
	body := e.get("/admin/users/" + id64(e.user.ID) + "/edit").Body.String()
	assert.Contains(t, body, "Koblingsinvitasjoner")
	assert.Contains(t, body, "Acme på svca")
	assert.Contains(t, body, "Acme på svcb")
	assert.NotContains(t, body, "skjult på", "avvist leverandør er ikke et valg")
	assert.NotContains(t, body, "Acme på svcc", "inaktiv tjeneste er ikke et valg")
	assert.Contains(t, body, testActor)
	assert.Contains(t, body, "/link-invites/")

	// Valget fra nedtrekket (pair) fungerer som provider+service.
	w := e.post("/admin/users/"+id64(e.user.ID)+"/link-invites", url.Values{"pair": {"acme:svcb"}})
	e.h.WaitForSends()
	require.Equal(t, http.StatusSeeOther, w.Code)

	_, err := e.sqldb.Exec(`UPDATE users SET deactivated_at = '2026-10-01T10:00:00Z' WHERE id = ?`, e.user.ID)
	require.NoError(t, err)
	body = e.get("/admin/users/" + id64(e.user.ID) + "/edit").Body.String()
	assert.NotContains(t, body, `name="pair"`)
	assert.Contains(t, body, "deaktivert")
}

func TestInviteCreate_AuditFailureFailsClosed(t *testing.T) {
	e := newInvEnv(t)
	e.h.auditor = failingAudit{}
	w := e.invite(e.user.ID, "acme", "svca")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "Invitasjonen ble ikke sendt fordi audit-loggen ikke kunne skrives")
	assert.Empty(t, e.mailer.all())
	rows := e.rows(t)
	require.Len(t, rows, 1)
	assert.NotNil(t, rows[0].UsedAt)
}

func TestInviteCreate_LocaleFollowsAcceptLanguage(t *testing.T) {
	e := newInvEnv(t)
	for _, c := range []struct{ header, want string }{{"de", "de"}, {"nb", "nb"}, {"en", "en"}} {
		req := formPost("/admin/users/"+id64(e.user.ID)+"/link-invites", url.Values{"provider": {"acme"}, "service": {"svcb"}})
		req.Header.Set("Accept-Language", c.header)
		e.mux.ServeHTTP(httptest.NewRecorder(), req)
		e.h.WaitForSends()
		sent := e.mailer.all()
		assert.Equal(t, c.want, sent[len(sent)-1].locale)
	}
}

func TestDeactivateBurnsInvites(t *testing.T) {
	e := newInvEnv(t)
	require.Equal(t, http.StatusSeeOther, e.invite(e.user.ID, "acme", "svca").Code)
	r := chi.NewRouter()
	r.Use(withActor)
	r.Post("/admin/users/{id}/deactivate", e.h.HandleDeactivate)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/admin/users/"+id64(e.user.ID)+"/deactivate", nil))
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.NotNil(t, e.rows(t)[0].UsedAt)
	_, details := e.auditRow(t, "user_deactivated")
	assert.Contains(t, details, "invites_burned=1")
}

func TestInvite_EmailChangeAuditCountsBurned(t *testing.T) {
	e := newInvEnv(t)
	require.Equal(t, http.StatusSeeOther, e.invite(e.user.ID, "acme", "svca").Code)
	e.post(emailPath(e.user.ID), url.Values{"email": {"ny@firma.no"}, "confirm": {"1"}})
	_, details := e.auditRow(t, "user_email_changed")
	assert.Contains(t, details, "invites_burned=1")
}
