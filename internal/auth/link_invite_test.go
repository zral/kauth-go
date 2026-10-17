package auth

import (
	"bytes"
	"context"
	"html/template"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/fetchmeta"
	"github.com/zral/kauth-go/internal/idp"
	"github.com/zral/kauth-go/internal/oidctest"
	"github.com/zral/kauth-go/internal/token"
)

type recMailer struct {
	mu   sync.Mutex
	sent []recMail
}

type recMail struct{ to, fromName, provider, locale, fromAddress string }

func (m *recMailer) SendLinkConfirmation(to, fromName, providerName, locale, fromAddress string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, recMail{to, fromName, providerName, locale, fromAddress})
	return nil
}

func (m *recMailer) all() []recMail {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]recMail(nil), m.sent...)
}

// lf er gf pluss koblingsflyten (/link/{token} og grenen i callbacken).
type lf struct {
	*gf
	links *LinkHandlers
	mail  *recMailer
	logs  *bytes.Buffer
}

func newLF(t *testing.T, o gfOpts) *lf {
	t.Helper()
	f := newGF(t, o)
	logs := &bytes.Buffer{}
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })

	ex := func(q string, args ...any) {
		t.Helper()
		_, err := f.sqldb.Exec(q, args...)
		require.NoError(t, err)
	}
	ex(`INSERT INTO identity_providers (id,slug,display_name,issuer,client_id) VALUES (1,'a','Acme ID',?,'client-a'),(2,'b','Beta ID',?,'client-b')`, f.a.Issuer(), f.b.Issuer())
	ex(`INSERT INTO service_identity_providers (service_id,provider_id,position) VALUES ('klarsyn',1,0),('klarsyn',2,1)`)
	if o.annen != "" {
		ex(`INSERT INTO service_identity_providers (service_id,provider_id,position) VALUES ('annen',1,0)`)
	}

	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)
	mail := &recMailer{}
	links := NewLinkHandlers(f.cfg, f.sqldb, f.q, f.reg, f.idps, f.aud, tmpl, mail)
	f.h.WithLinks(links)
	f.mux.Get("/link/{token}", links.ShowConfirm)
	f.mux.With(fetchmeta.Middleware).Post("/link/{token}", links.StartLink)
	return &lf{gf: f, links: links, mail: mail, logs: logs}
}

// invite lager en gyldig invitasjon og returnerer klartekst-tokenet og id-en.
func (l *lf) invite(u gen.User, providerID int64, svcID string, expiresIn time.Duration) (string, int64) {
	l.t.Helper()
	plain, hash, err := token.NewLinkInviteToken()
	require.NoError(l.t, err)
	now := time.Now()
	n, err := l.q.InsertLinkInviteLimited(context.Background(), gen.InsertLinkInviteLimitedParams{
		TokenHash: hash, UserID: u.ID, ProviderID: providerID, ServiceID: svcID, Email: NormalizeEmail(u.Email),
		CreatedBy: "admin@firma.no", CreatedAt: token.FormatLinkInviteTime(now),
		ExpiresAt:   token.FormatLinkInviteTime(now.Add(expiresIn)),
		WindowStart: token.FormatLinkInviteTime(now.Add(-time.Hour)),
	})
	require.NoError(l.t, err)
	require.EqualValues(l.t, 1, n)
	inv, err := l.q.GetLinkInviteByID(context.Background(), l.lastInviteID())
	require.NoError(l.t, err)
	return plain, inv.ID
}

func (l *lf) lastInviteID() int64 {
	var id int64
	require.NoError(l.t, l.sqldb.QueryRow(`SELECT MAX(id) FROM identity_link_invites`).Scan(&id))
	return id
}

func (l *lf) used(id int64) bool {
	l.t.Helper()
	return l.count(`SELECT COUNT(*) FROM identity_link_invites WHERE id = ? AND used_at IS NOT NULL`, id) == 1
}

func (l *lf) idCount(issuer string) int {
	return l.count(`SELECT COUNT(*) FROM user_identities WHERE issuer = ?`, issuer)
}

// Sidene testes på norsk; uten Accept-Language velger i18n engelsk.
func (l *lf) get(plain string, query string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/link/"+plain+query, nil)
	req.Header.Set("Accept-Language", "nb")
	return l.serve(req)
}

func (l *lf) callbackAt(slug string, u *url.URL, cookie string) *httptest.ResponseRecorder {
	l.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/idp/"+slug+"/callback?"+u.RawQuery, nil)
	req.Header.Set("Accept-Language", "nb")
	req.AddCookie(&http.Cookie{Name: idpStateCookie, Value: cookie})
	return l.serve(req)
}

func (l *lf) post(plain string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/link/"+plain, nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Accept-Language", "nb")
	return l.serve(req)
}

// startAndAuthorize kjører POST /link/{token} og leverandørens authorize, og
// returnerer URL-en leverandøren sender brukeren tilbake til, med cookien.
func (l *lf) startAndAuthorize(plain string, c oidctest.Claims) (*url.URL, string) {
	l.t.Helper()
	l.a.Next(c, oidctest.ModeOK)
	w := l.post(plain)
	sc := cookieNamed(w, idpStateCookie)
	require.NotNil(l.t, sc, w.Body.String())
	return l.authorize(w), sc.Value
}

// fullFlow er hele veien fra POST til callback.
func (l *lf) fullFlow(plain string, c oidctest.Claims) *httptest.ResponseRecorder {
	l.t.Helper()
	u, cookie := l.startAndAuthorize(plain, c)
	return l.callbackAt("a", u, cookie)
}

// forgeAuthorize går mot leverandørens authorize med en vilkårlig (men gyldig
// signert) state, og returnerer callback-URL-en.
func (l *lf) forgeAuthorize(fake *oidctest.IdP, clientID, slug, state, nonce string) *url.URL {
	l.t.Helper()
	cfg := &oauth2.Config{ClientID: clientID, Endpoint: oauth2.Endpoint{AuthURL: fake.URL() + "/authorize"},
		RedirectURL: "http://" + gfHost + "/idp/" + slug + "/callback", Scopes: []string{"openid", "email", "profile"}}
	au := cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(idp.PKCEVerifier(l.cfg.OIDCStateSecret, state)), oidc.Nonce(nonce))
	resp, err := noRedirect.Get(au)
	require.NoError(l.t, err)
	resp.Body.Close()
	require.Equal(l.t, http.StatusFound, resp.StatusCode)
	u, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(l.t, err)
	return u
}

func linkClaims(sub string) oidctest.Claims {
	return oidctest.Claims{Sub: sub, Email: "annen-adresse@leverandor.test", EmailVerified: oidctest.EVTrue, Name: "Kari"}
}

func requireResultPage(t *testing.T, w *httptest.ResponseRecorder, status int, title string) {
	t.Helper()
	require.Equal(t, status, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), title)
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	require.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
	require.Empty(t, w.Header().Get("Location"), "kobling sender aldri brukeren videre")
}

// requireNoSession låser K17: ingen annen cookie enn slettingen av idp_state.
func requireNoSession(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		require.Equal(t, idpStateCookie, c.Name, "uventet cookie: %s", c.Name)
		require.Less(t, c.MaxAge, 0, "idp_state skal slettes")
	}
	require.NotContains(t, w.Body.String(), "token=")
}

// --- GET ---

func TestLinkGET_ShowsConfirmationAndChangesNothing(t *testing.T) {
	l := newLF(t, gfOpts{})
	u := l.user("kari@firma.no", "user")
	plain, id := l.invite(u, 1, "klarsyn", time.Hour)

	w := l.get(plain, "")
	requireResultPage(t, w, http.StatusOK, "Koble til Acme ID")
	body := w.Body.String()
	require.Contains(t, body, "<strong>k***@firma.no</strong>")
	require.Contains(t, body, "<strong>Acme ID</strong>")
	require.Contains(t, body, "Kjenner du ikke igjen denne brukeren, skal du ikke fortsette.")
	require.NotContains(t, body, "kari@firma.no")
	require.Contains(t, body, `method="post" action="/link/`+plain+`?lang=nb"`)
	require.Contains(t, body, "Fortsett til Acme ID")
	require.Nil(t, cookieNamed(w, idpStateCookie))
	require.False(t, l.used(id))
	require.Equal(t, 0, l.count(`SELECT COUNT(*) FROM user_identities`))
	require.Equal(t, 0, l.idCount(l.a.Issuer()))

	// Samme lenke igjen: fortsatt gyldig.
	requireResultPage(t, l.get(plain, ""), http.StatusOK, "Koble til Acme ID")

	we := l.get(plain, "?lang=en")
	require.Contains(t, we.Body.String(), "Link Acme ID")
	require.Contains(t, we.Body.String(), "k***@firma.no")
}

func TestMaskEmail(t *testing.T) {
	for in, want := range map[string]string{
		"kari@firma.no": "k***@firma.no", "a@b.no": "a***@b.no", "øyvind@firma.no": "ø***@firma.no",
		"": "***", "uten-snabel-a": "***", "@firma.no": "***",
	} {
		require.Equal(t, want, maskEmail(in), in)
	}
}

func TestLinkInvalid_AllCasesGiveIdenticalResponse(t *testing.T) {
	l := newLF(t, gfOpts{annen: "inactive"})
	ctx := context.Background()
	mk := func(email string) gen.User { return l.user(email, "user") }

	expired, _ := l.invite(mk("u1@firma.no"), 1, "klarsyn", -time.Hour)
	usedPlain, usedID := l.invite(mk("u2@firma.no"), 1, "klarsyn", time.Hour)
	_, err := l.sqldb.Exec(`UPDATE identity_link_invites SET used_at = ? WHERE id = ?`, token.FormatLinkInviteTime(time.Now()), usedID)
	require.NoError(t, err)
	revUser := mk("u3@firma.no")
	revoked, revID := l.invite(revUser, 1, "klarsyn", time.Hour)
	n, err := l.q.RevokeLinkInvite(ctx, gen.RevokeLinkInviteParams{ID: revID, UserID: revUser.ID, Now: token.FormatLinkInviteTime(time.Now())})
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	changed, _ := l.invite(mk("u4@firma.no"), 1, "klarsyn", time.Hour)
	_, err = l.sqldb.Exec(`UPDATE users SET email = 'ny@firma.no' WHERE email = 'u4@firma.no'`)
	require.NoError(t, err)
	deactivated, _ := l.invite(mk("u5@firma.no"), 1, "klarsyn", time.Hour)
	_, err = l.sqldb.Exec(`UPDATE users SET deactivated_at = ? WHERE email = 'u5@firma.no'`, t0)
	require.NoError(t, err)
	inactiveSvc, _ := l.invite(mk("u6@firma.no"), 1, "annen", time.Hour)
	unassigned, _ := l.invite(mk("u7@firma.no"), 2, "klarsyn", time.Hour)
	_, err = l.sqldb.Exec(`DELETE FROM service_identity_providers WHERE provider_id = 2`)
	require.NoError(t, err)
	require.NoError(t, l.idps.ReloadAssignments(ctx, l.q))

	cases := map[string]string{
		"ukjent":                 strings.Repeat("A", 43),
		"feil format (kort)":     "kort",
		"feil format (tegn)":     strings.Repeat("!", 43),
		"feil format (lang)":     strings.Repeat("A", 44),
		"utløpt":                 expired,
		"brukt":                  usedPlain,
		"tilbakekalt":            revoked,
		"e-post endret":          changed,
		"bruker deaktivert":      deactivated,
		"tjeneste inaktiv":       inactiveSvc,
		"leverandør avtilordnet": unassigned,
	}
	var want *httptest.ResponseRecorder
	for name, tok := range cases {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			var w *httptest.ResponseRecorder
			if method == http.MethodGet {
				w = l.get(tok, "")
			} else {
				w = l.post(tok)
			}
			requireResultPage(t, w, http.StatusOK, "Lenken er ugyldig eller utløpt")
			if want == nil {
				want = w
			}
			require.Equal(t, want.Body.String(), w.Body.String(), "%s %s", method, name)
			require.Equal(t, want.Header(), w.Header(), "%s %s", method, name)
			require.Nil(t, cookieNamed(w, idpStateCookie), "%s %s", method, name)
		}
	}
	require.Equal(t, 0, l.count(`SELECT COUNT(*) FROM user_identities`))
}

// --- POST ---

func TestLinkPOST_CrossOriginIsForbidden(t *testing.T) {
	l := newLF(t, gfOpts{})
	plain, id := l.invite(l.user("kari@firma.no", "user"), 1, "klarsyn", time.Hour)
	for _, hdr := range []map[string]string{
		{"Sec-Fetch-Site": "cross-site"},
		{"Sec-Fetch-Site": "same-site"},
		{"Origin": "https://evil.test"},
		{},
	} {
		req := httptest.NewRequest(http.MethodPost, "/link/"+plain, nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		w := l.serve(req)
		require.Equal(t, http.StatusForbidden, w.Code, "%v", hdr)
		require.Nil(t, cookieNamed(w, idpStateCookie))
		require.Empty(t, w.Header().Get("Location"))
	}
	require.False(t, l.used(id))
}

func TestLinkPOST_RedirectsToProviderWithPKCEAndNonce(t *testing.T) {
	l := newLF(t, gfOpts{})
	plain, id := l.invite(l.user("kari@firma.no", "user"), 1, "klarsyn", time.Hour)

	w := l.post(plain)
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	require.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, l.a.URL()+"/authorize", loc.Scheme+"://"+loc.Host+loc.Path)
	q := loc.Query()
	require.Equal(t, "code", q.Get("response_type"))
	require.Equal(t, "client-a", q.Get("client_id"))
	require.Equal(t, "http://klarsyn.net/idp/a/callback", q.Get("redirect_uri"))
	require.Equal(t, "S256", q.Get("code_challenge_method"))
	require.NotEmpty(t, q.Get("code_challenge"))
	require.NotEmpty(t, q.Get("nonce"))
	require.Equal(t, "login", q.Get("prompt"), "kobling krever ny autentisering hos leverandøren")
	require.NotContains(t, l.start("a", "?service=klarsyn").Header().Get("Location"), "prompt=", "vanlig innlogging har ikke prompt")

	sc := cookieNamed(w, idpStateCookie)
	require.NotNil(t, sc)
	require.Equal(t, q.Get("state"), sc.Value)
	require.True(t, sc.HttpOnly)
	require.Equal(t, http.SameSiteLaxMode, sc.SameSite)
	require.Equal(t, 600, sc.MaxAge)
	require.Nil(t, cookieNamed(w, "redirect_uri"), "kobling bruker ikke redirect_uri")

	c, ok := parseState(l.cfg.OIDCStateSecret, sc.Value)
	require.True(t, ok)
	require.Equal(t, stateClaims{ServiceID: "klarsyn", Nonce: q.Get("nonce"), IDP: "a", Link: id}, c)
	require.False(t, l.used(id), "POST brenner ikke invitasjonen")
	require.Equal(t, 0, l.idCount(l.a.Issuer()))
}

func TestLinkPOST_DiscoveryFailureKeepsInviteValid(t *testing.T) {
	l := newLF(t, gfOpts{withDown: true})
	_, err := l.sqldb.Exec(`INSERT INTO identity_providers (id,slug,display_name,issuer,client_id) VALUES (3,'c','Ned ID',?,'client-c')`, l.c.Issuer())
	require.NoError(t, err)
	_, err = l.sqldb.Exec(`INSERT INTO service_identity_providers (service_id,provider_id,position) VALUES ('klarsyn',3,2)`)
	require.NoError(t, err)
	plain, id := l.invite(l.user("kari@firma.no", "user"), 3, "klarsyn", time.Hour)

	w := l.post(plain)
	requireResultPage(t, w, http.StatusBadGateway, "Koblingen gikk ikke")
	require.Nil(t, cookieNamed(w, idpStateCookie))
	require.False(t, l.used(id))
	require.Contains(t, l.rejectedLinkDetails(), "invite="+itoa(id)+" provider=c reason=discovery")
}

// --- Full flyt ---

func TestLinkFlow_LinksIdentityToInvitedUser(t *testing.T) {
	l := newLF(t, gfOpts{})
	u := l.user("kari@firma.no", "user")
	plain, id := l.invite(u, 1, "klarsyn", time.Hour)

	w := l.fullFlow(plain, linkClaims("sub-secret-123"))
	requireResultPage(t, w, http.StatusOK, "Koblet")
	require.Contains(t, w.Body.String(), "Acme ID er koblet til brukeren din")
	requireNoSession(t, w)

	var userID, adminOK int64
	var provider string
	var email *string
	require.NoError(t, l.sqldb.QueryRow(`SELECT user_id, provider, admin_ok, email FROM user_identities WHERE issuer = ? AND subject = ?`,
		l.a.Issuer(), "sub-secret-123").Scan(&userID, &provider, &adminOK, &email))
	require.Equal(t, u.ID, userID)
	require.Equal(t, "oidc", provider)
	require.EqualValues(t, 0, adminOK)
	require.NotNil(t, email)
	require.Equal(t, "annen-adresse@leverandor.test", *email, "e-postpåstanden lagres, men avgjør ikke koblingen")
	require.True(t, l.used(id))
	require.Equal(t, 0, l.count(`SELECT COUNT(*) FROM refresh_tokens`))

	l.links.WaitForSends()
	sent := l.mail.all()
	require.Len(t, sent, 1)
	require.Equal(t, "kari@firma.no", sent[0].to)
	require.Equal(t, "Acme ID", sent[0].provider)

	evs := l.events()
	linked := lbOfType(evs, "identity_linked")
	require.Len(t, linked, 1)
	var identityID int64
	require.NoError(t, l.sqldb.QueryRow(`SELECT id FROM user_identities WHERE subject = 'sub-secret-123'`).Scan(&identityID))
	require.Equal(t, "via=invite invite="+itoa(id)+" provider=a issuer="+l.a.Issuer()+" identity_id="+itoa(identityID), *linked[0].Details)
	require.Equal(t, "kari@firma.no", *linked[0].Email)
	require.Equal(t, "klarsyn", *linked[0].ServiceID)
	require.EqualValues(t, 1, linked[0].Success)
	require.Empty(t, lbOfType(evs, "identity_link_rejected"))
	require.Empty(t, lbOfType(evs, "oidc_login"), "kobling er ikke innlogging")
}

func TestLinkFlow_NextLoginWithSameAccountIsOIDCLogin(t *testing.T) {
	l := newLF(t, gfOpts{})
	u := l.user("kari@firma.no", "user")
	plain, _ := l.invite(u, 1, "klarsyn", time.Hour)
	requireResultPage(t, l.fullFlow(plain, linkClaims("sub-1")), http.StatusOK, "Koblet")

	w := l.run(l.a, "a", oidctest.Claims{Sub: "sub-1", Email: "annen-adresse@leverandor.test", EmailVerified: oidctest.EVTrue}, oidctest.ModeOK)
	requireDispatch(t, w)
	logins := lbOfType(l.events(), "oidc_login")
	require.Len(t, logins, 1)
	require.Equal(t, "kari@firma.no", *logins[0].Email)
}

func TestLinkFlow_TrustEmailIsIrrelevant(t *testing.T) {
	// Leverandøren er ikke betrodd for e-post (trustA false) og påstanden
	// matcher ikke brukeren, men lenken er beviset.
	l := newLF(t, gfOpts{trustA: false})
	u := l.user("kari@firma.no", "user")
	plain, _ := l.invite(u, 1, "klarsyn", time.Hour)
	c := linkClaims("sub-x")
	c.EmailVerified = oidctest.EVFalse
	requireResultPage(t, l.fullFlow(plain, c), http.StatusOK, "Koblet")
	require.Equal(t, 1, l.idCount(l.a.Issuer()))
}

func TestLinkFlow_SecondCallbackWithSameInviteGivesOneLink(t *testing.T) {
	l := newLF(t, gfOpts{})
	u := l.user("kari@firma.no", "user")
	plain, id := l.invite(u, 1, "klarsyn", time.Hour)

	u1, c1 := l.startAndAuthorize(plain, linkClaims("sub-1"))
	u2, c2 := l.startAndAuthorize(plain, linkClaims("sub-2"))

	requireResultPage(t, l.callbackAt("a", u1, c1), http.StatusOK, "Koblet")
	w2 := l.callbackAt("a", u2, c2)
	requireResultPage(t, w2, http.StatusBadRequest, "Koblingen gikk ikke")
	requireNoSession(t, w2)

	require.Equal(t, 1, l.idCount(l.a.Issuer()))
	require.Equal(t, 1, l.count(`SELECT COUNT(*) FROM user_identities WHERE subject = 'sub-1'`))
	require.True(t, l.used(id))
	l.links.WaitForSends()
	require.Len(t, l.mail.all(), 1)
	require.Contains(t, l.rejectedLinkDetails(), "invite="+itoa(id)+" provider=a reason=invite_invalid")
}

func TestLinkFlow_ConcurrentCallbacksGiveAtMostOneLink(t *testing.T) {
	l := newLF(t, gfOpts{})
	u := l.user("kari@firma.no", "user")
	plain, _ := l.invite(u, 1, "klarsyn", time.Hour)
	const n = 4
	urls := make([]*url.URL, n)
	cookies := make([]string, n)
	for i := range urls {
		urls[i], cookies[i] = l.startAndAuthorize(plain, linkClaims("sub-"+itoa(int64(i))))
	}
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := range urls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = l.callbackAt("a", urls[i], cookies[i]).Code
		}()
	}
	wg.Wait()
	ok := 0
	for _, c := range codes {
		if c == http.StatusOK {
			ok++
		}
	}
	require.Equal(t, 1, ok, "%v", codes)
	require.Equal(t, 1, l.idCount(l.a.Issuer()))
}

func TestLinkFlow_SubOwnedByOtherUserIsRejectedAndInviteStaysValid(t *testing.T) {
	l := newLF(t, gfOpts{})
	owner := l.user("eier@firma.no", "user")
	l.link(owner.ID, l.a.Issuer(), "sub-eid")
	u := l.user("kari@firma.no", "user")
	plain, id := l.invite(u, 1, "klarsyn", time.Hour)

	w := l.fullFlow(plain, linkClaims("sub-eid"))
	requireResultPage(t, w, http.StatusBadRequest, "Koblingen gikk ikke")
	requireNoSession(t, w)
	require.False(t, l.used(id), "invitasjonen er ubrukt etter rollback")
	var uid int64
	require.NoError(t, l.sqldb.QueryRow(`SELECT user_id FROM user_identities WHERE subject = 'sub-eid'`).Scan(&uid))
	require.Equal(t, owner.ID, uid, "eksisterende identitet overskrives aldri")
	l.links.WaitForSends()
	require.Empty(t, l.mail.all())
	require.Contains(t, l.rejectedLinkDetails(), "invite="+itoa(id)+" provider=a reason=identity_taken")

	// Lenken virker fortsatt, med en annen konto hos leverandøren.
	requireResultPage(t, l.fullFlow(plain, linkClaims("sub-kari")), http.StatusOK, "Koblet")
}

func TestLinkFlow_SameSubSameUserIsAlreadyLinked(t *testing.T) {
	l := newLF(t, gfOpts{})
	u := l.user("kari@firma.no", "user")
	l.link(u.ID, l.a.Issuer(), "sub-1")
	plain, id := l.invite(u, 1, "klarsyn", time.Hour)

	w := l.fullFlow(plain, linkClaims("sub-1"))
	requireResultPage(t, w, http.StatusOK, "Allerede koblet")
	requireNoSession(t, w)
	require.True(t, l.used(id))
	require.Equal(t, 1, l.idCount(l.a.Issuer()))
	l.links.WaitForSends()
	require.Empty(t, l.mail.all(), "ingen ny kobling, ingen kvittering")
	linked := lbOfType(l.events(), "identity_linked")
	require.Len(t, linked, 1)
	require.Contains(t, *linked[0].Details, "already=1")
}

func TestLinkFlow_NewSubForUserWithExistingIdentityIsAdded(t *testing.T) {
	l := newLF(t, gfOpts{})
	u := l.user("kari@firma.no", "user")
	l.link(u.ID, l.a.Issuer(), "sub-gammel")
	plain, _ := l.invite(u, 1, "klarsyn", time.Hour)

	requireResultPage(t, l.fullFlow(plain, linkClaims("sub-ny")), http.StatusOK, "Koblet")
	require.Equal(t, 2, l.count(`SELECT COUNT(*) FROM user_identities WHERE user_id = ? AND issuer = ?`, u.ID, l.a.Issuer()))
	require.Equal(t, 1, l.count(`SELECT COUNT(*) FROM user_identities WHERE subject = 'sub-gammel'`))
}

func TestLinkCallback_RejectionsBetweenPOSTAndCallback(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(l *lf, u gen.User)
		reason string // tom: avvist av eksisterende verifisering før grenen
	}{
		{"bruker deaktivert", func(l *lf, u gen.User) {
			_, err := l.sqldb.Exec(`UPDATE users SET deactivated_at = ? WHERE id = ?`, t0, u.ID)
			require.NoError(t, err)
		}, "user_inactive"},
		{"e-post endret", func(l *lf, u gen.User) {
			_, err := l.sqldb.Exec(`UPDATE users SET email = 'ny@firma.no' WHERE id = ?`, u.ID)
			require.NoError(t, err)
		}, "email_changed"},
		{"invitasjon utløpt", func(l *lf, u gen.User) {
			_, err := l.sqldb.Exec(`UPDATE identity_link_invites SET expires_at = ? WHERE user_id = ?`, "2020-01-01T00:00:00Z", u.ID)
			require.NoError(t, err)
		}, "invite_invalid"},
		{"invitasjon tilbakekalt", func(l *lf, u gen.User) {
			_, err := l.sqldb.Exec(`UPDATE identity_link_invites SET used_at = ? WHERE user_id = ?`, t0, u.ID)
			require.NoError(t, err)
		}, "invite_invalid"},
		{"leverandør avtilordnet", func(l *lf, u gen.User) {
			_, err := l.sqldb.Exec(`DELETE FROM service_identity_providers WHERE provider_id = 1`)
			require.NoError(t, err)
			require.NoError(t, l.idps.ReloadAssignments(context.Background(), l.q))
		}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := newLF(t, gfOpts{})
			u := l.user("kari@firma.no", "user")
			plain, id := l.invite(u, 1, "klarsyn", time.Hour)
			cb, cookie := l.startAndAuthorize(plain, linkClaims("sub-1"))
			tc.mutate(l, u)

			w := l.callbackAt("a", cb, cookie)
			if tc.reason == "" {
				requireLoginError(t, w, "login_failed", "klarsyn")
			} else {
				requireResultPage(t, w, http.StatusBadRequest, "Koblingen gikk ikke")
				requireNoSession(t, w)
				require.Contains(t, l.rejectedLinkDetails(), "invite="+itoa(id)+" provider=a reason="+tc.reason)
			}
			require.Equal(t, 0, l.idCount(l.a.Issuer()), "ingen kobling")
			l.links.WaitForSends()
			require.Empty(t, l.mail.all())
		})
	}
}

func TestLinkCallback_PreBranchRejectionCarriesInviteID(t *testing.T) {
	l := newLF(t, gfOpts{})
	plain, id := l.invite(l.user("kari@firma.no", "user"), 1, "klarsyn", time.Hour)
	cb, cookie := l.startAndAuthorize(plain, linkClaims("sub-1"))
	q := cb.Query()
	q.Set("error", "access_denied")
	cb.RawQuery = q.Encode()
	requireLoginError(t, l.callbackAt("a", cb, cookie), "login_failed", "klarsyn")
	rej := lbOfType(l.events(), "oidc_rejected")
	require.Len(t, rej, 1)
	require.Equal(t, "provider=a invite="+itoa(id)+" reason=provider_error", *rej[0].Details)
	require.False(t, l.used(id))
}

// admin_ok settes aldri av koblingen: InsertIdentity har ingen admin_ok-kolonne
// (DB-default 0), og CHECK (provider <> 'oidc' OR admin_ok = 0) i user_identities
// gjør det umulig å lagre en oidc-rad med admin_ok=1. Full-flyt-testen over
// leser admin_ok=0 fra raden.

func TestLinkCallback_UnknownServiceInStateLinksNothing(t *testing.T) {
	l := newLF(t, gfOpts{})
	plain, id := l.invite(l.user("kari@firma.no", "user"), 1, "klarsyn", time.Hour)
	_ = plain
	state := signLinkState(l.cfg.OIDCStateSecret, "finnes-ikke", "n1", "a", id)
	l.a.Next(linkClaims("sub-1"), oidctest.ModeOK)
	cb := l.forgeAuthorize(l.a, "client-a", "a", state, "n1")
	w := l.callbackAt("a", cb, state)
	requireLoginError(t, w, "login_failed", "")
	require.Equal(t, 0, l.idCount(l.a.Issuer()))
	require.False(t, l.used(id))
}

func TestLinkCallback_ServiceMustEqualInvitesService(t *testing.T) {
	l := newLF(t, gfOpts{annen: "assigned"})
	_, id := l.invite(l.user("kari@firma.no", "user"), 1, "klarsyn", time.Hour)
	// Leverandør a er tilordnet både klarsyn og annen, så all øvrig
	// verifisering består; bare invitasjonens tjeneste skiller dem.
	state := signLinkState(l.cfg.OIDCStateSecret, "annen", "n1", "a", id)
	l.a.Next(linkClaims("sub-1"), oidctest.ModeOK)
	cb := l.forgeAuthorize(l.a, "client-a", "a", state, "n1")
	w := l.callbackAt("a", cb, state)
	requireResultPage(t, w, http.StatusBadRequest, "Koblingen gikk ikke")
	require.Equal(t, 0, l.idCount(l.a.Issuer()))
	require.False(t, l.used(id))
	require.Contains(t, l.rejectedLinkDetails(), "reason=invite_invalid")
}

func TestLinkCallback_StateForOtherProviderCannotConsumeInvite(t *testing.T) {
	l := newLF(t, gfOpts{})
	_, id := l.invite(l.user("kari@firma.no", "user"), 1, "klarsyn", time.Hour)
	// Gyldig signert state for invitasjon til leverandør a, men kjørt mot b.
	state := signLinkState(l.cfg.OIDCStateSecret, "klarsyn", "n1", "b", id)
	l.b.Next(oidctest.Claims{Sub: "sub-b", Email: "kari@example.test", EmailVerified: oidctest.EVTrue}, oidctest.ModeOK)
	cb := l.forgeAuthorize(l.b, "client-b", "b", state, "n1")
	w := l.callbackAt("b", cb, state)
	requireResultPage(t, w, http.StatusBadRequest, "Koblingen gikk ikke")
	require.Equal(t, 0, l.idCount(l.b.Issuer()))
	require.False(t, l.used(id))
}

func TestLinkCallback_StateForInviteACannotBeUsedForB(t *testing.T) {
	l := newLF(t, gfOpts{})
	ua := l.user("a@firma.no", "user")
	ub := l.user("b@firma.no", "user")
	plainA, idA := l.invite(ua, 1, "klarsyn", time.Hour)
	_, idB := l.invite(ub, 1, "klarsyn", time.Hour)

	cb, cookie := l.startAndAuthorize(plainA, linkClaims("sub-a"))
	// Bytter id i den signerte staten (både i cookie og i state-parameter).
	forged := tamperLinkID(t, cookie, "link="+itoa(idA), "link="+itoa(idB))
	q := cb.Query()
	q.Set("state", forged)
	cb.RawQuery = q.Encode()
	w := l.callbackAt("a", cb, forged)
	requireLoginError(t, w, "login_failed", "")
	require.False(t, l.used(idA))
	require.False(t, l.used(idB))
	require.Equal(t, 0, l.idCount(l.a.Issuer()))
}

func TestLinkCallback_WithoutLinkHandlersLinkStateIsRejected(t *testing.T) {
	l := newLF(t, gfOpts{})
	plain, id := l.invite(l.user("kari@firma.no", "user"), 1, "klarsyn", time.Hour)
	cb, cookie := l.startAndAuthorize(plain, linkClaims("sub-1"))
	l.h.links = nil
	w := l.callbackAt("a", cb, cookie)
	requireLoginError(t, w, "login_failed", "klarsyn")
	require.Equal(t, 0, l.idCount(l.a.Issuer()))
	require.False(t, l.used(id))
}

// --- Vanlig innlogging og andre callbacks ---

func TestLinkState_RejectedByGoogleMicrosoftAndAdminCallback(t *testing.T) {
	l := newLF(t, gfOpts{})
	_, id := l.invite(l.user("kari@firma.no", "user"), 1, "klarsyn", time.Hour)
	state := signLinkState(l.cfg.OIDCStateSecret, "klarsyn", "n1", "a", id)

	for _, tc := range []struct{ path, cookie string }{
		{"/callback", "oidc_state"},  // Google, også admin-flyten (admin-formålet ligger i staten)
		{"/ms-callback", "ms_state"}, // Microsoft
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path+"?code=x&state="+url.QueryEscape(state), nil)
		req.AddCookie(&http.Cookie{Name: tc.cookie, Value: state})
		w := l.serve(req)
		requireLoginError(t, w, "login_failed", "")
		require.Nil(t, cookieNamed(w, "refresh_token"), tc.path)
	}
	require.False(t, l.used(id))
	require.Equal(t, 0, l.count(`SELECT COUNT(*) FROM user_identities`))
	// Ingen av dem nådde leverandør- eller tjenesteoppslag.
	require.Empty(t, l.events())
}

func TestLinkState_NeverProducedByOrdinaryLogin(t *testing.T) {
	l := newLF(t, gfOpts{})
	u := l.user("kari@firma.no", "user")
	_, id := l.invite(u, 1, "klarsyn", time.Hour)

	w := l.start("a", "?service=klarsyn")
	c, ok := parseState(l.cfg.OIDCStateSecret, cookieNamed(w, idpStateCookie).Value)
	require.True(t, ok)
	require.Zero(t, c.Link)

	// En vanlig idp-innlogging med brukerens e-post (uten betrodd e-post)
	// utløser ikke kobling og røre ikke invitasjonen.
	res := l.run(l.a, "a", oidctest.Claims{Sub: "sub-ny", Email: "kari@firma.no", EmailVerified: oidctest.EVTrue}, oidctest.ModeOK)
	requireLoginError(t, res, "access_denied", "klarsyn")
	require.False(t, l.used(id))
	require.Equal(t, 0, l.idCount(l.a.Issuer()))
	require.Empty(t, lbOfType(l.events(), "identity_linked"))
}

// --- Hemmeligheter ---

func TestLinkFlow_SubAndTokenNeverInAuditOrLogs(t *testing.T) {
	l := newLF(t, gfOpts{})
	owner := l.user("eier@firma.no", "user")
	l.link(owner.ID, l.a.Issuer(), "sub-hemmelig-eid")
	u := l.user("kari@firma.no", "user")
	plain, _ := l.invite(u, 1, "klarsyn", time.Hour)

	// Ett avslag, én kobling og ett gjenbruk.
	l.fullFlow(plain, linkClaims("sub-hemmelig-eid"))
	cb, cookie := l.startAndAuthorize(plain, linkClaims("sub-hemmelig-kari"))
	l.get(plain, "")
	l.callbackAt("a", cb, cookie)
	l.callbackAt("a", cb, cookie)
	l.links.WaitForSends()

	var dump strings.Builder
	for _, ev := range l.events() {
		for _, p := range []*string{ev.AuthMethod, ev.Email, ev.ServiceID, ev.IpAddress, ev.UserAgent, ev.Details} {
			if p != nil {
				dump.WriteString(*p + "\n")
			}
		}
	}
	require.Contains(t, dump.String(), "invite=", "audit-radene finnes")
	for _, secret := range []string{"sub-hemmelig-eid", "sub-hemmelig-kari", plain, token.HashOpaque(plain)} {
		require.NotContains(t, dump.String(), secret, "audit")
		require.NotContains(t, l.logs.String(), secret, "slog")
	}
	require.NotContains(t, l.logs.String(), gfLeakMarker)
}

func TestLinkRequestLog_MasksTokenInPath(t *testing.T) {
	for in, want := range map[string]string{
		"/link/" + strings.Repeat("A", 43): "/link/***",
		"/Link/abc":                        "/Link/***",
		"//link/abc/def":                   "/link/***",
		"/./link/abc":                      "/link/***",
		"/link":                            "/link",
		"/admin/users/5/link-invites":      "/admin/users/5/link-invites",
	} {
		require.Equal(t, want, maskPath(in), in)
	}

	// Gjennom hele kjeden, også når ruten ikke matcher.
	var buf bytes.Buffer
	r := chi.NewRouter()
	r.Use(RequestLogger(newTestLogger(&buf)))
	r.Get("/link/{token}", func(w http.ResponseWriter, _ *http.Request) {})
	tok := strings.Repeat("Q", 43)
	serveLogged(r, http.MethodGet, "/link/"+tok)
	serveLogged(r, http.MethodGet, "/link/"+tok+"/ekstra")
	require.NotContains(t, buf.String(), tok)
	require.Contains(t, buf.String(), "/link/{token}")
}

// rejectedLinkDetails henter Details fra alle identity_link_rejected-rader.
// Tømmer audit-køen, så den kan bare brukes sist i en test.
func (l *lf) rejectedLinkDetails() string {
	l.t.Helper()
	var out []string
	for _, ev := range lbOfType(l.events(), "identity_link_rejected") {
		require.NotNil(l.t, ev.Details)
		require.EqualValues(l.t, 0, ev.Success)
		require.NotNil(l.t, ev.ServiceID)
		out = append(out, *ev.Details)
	}
	return strings.Join(out, "\n")
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
