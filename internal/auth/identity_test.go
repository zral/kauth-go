package auth

import (
	"context"
	"database/sql"
	"html/template"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

const (
	testIssuer = "https://accounts.google.com"
	t0         = "2026-01-01T00:00:00Z"
)

type resolveFx struct {
	db *sql.DB
	r  *identityResolver
	q  *gen.Queries
}

// newResolveFx bruker en SQLite-fil (ikke :memory:) slik at flere tilkoblinger
// og skrivelåsen oppfører seg som i prod.
func newResolveFx(t *testing.T) *resolveFx {
	t.Helper()
	sqldb, q, err := db.Open(filepath.Join(t.TempDir(), "id.db"))
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })
	aud := audit.NewService(q)
	t.Cleanup(func() { aud.Close(context.Background()) })
	return &resolveFx{db: sqldb, r: newIdentityResolver(sqldb, aud), q: q}
}

func (f *resolveFx) user(t *testing.T, email string) gen.User {
	t.Helper()
	u, err := f.q.CreateUser(context.Background(), gen.CreateUserParams{PublicID: token.MustNewPublicID(), Email: email, Roles: "user", CreatedAt: t0})
	require.NoError(t, err)
	return u
}

func (f *resolveFx) identity(t *testing.T, userID int64, sub string) {
	t.Helper()
	n, err := f.q.InsertIdentity(context.Background(), gen.InsertIdentityParams{UserID: userID, Provider: "google", Issuer: testIssuer, Subject: sub, CreatedAt: t0})
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
}

// auditTypes venter på at skriveren har tømt køen for hendelser av typen.
func (f *resolveFx) auditTypes(t *testing.T, typ string) []gen.AuditEvent {
	t.Helper()
	var out []gen.AuditEvent
	require.Eventually(t, func() bool {
		all, err := f.q.ListAuditEvents(context.Background(), gen.ListAuditEventsParams{Limit: 100})
		require.NoError(t, err)
		out = out[:0]
		for _, e := range all {
			if e.EventType == typ {
				out = append(out, e)
			}
		}
		return len(out) >= 1
	}, 2*time.Second, 10*time.Millisecond)
	return out
}

func gext(sub, email string) externalIdentity {
	return externalIdentity{Provider: "google", Issuer: testIssuer, Subject: sub, Email: email, Name: "N"}
}

func TestResolve(t *testing.T) {
	ctx := context.Background()
	t.Run("kjent identitet gir A selv med e-post B (K3)", func(t *testing.T) {
		f := newResolveFx(t)
		a := f.user(t, "a@x.no")
		f.user(t, "b@x.no")
		f.identity(t, a.ID, "s1")
		u, out, err := f.r.resolve(ctx, gext("s1", "b@x.no"), linkPolicy{AutoLink: true}, resolveMeta{})
		require.NoError(t, err)
		require.Equal(t, a.ID, u.ID)
		require.Equal(t, outcomeMatched, out)
		mm := f.auditTypes(t, "identity_email_mismatch")
		require.Len(t, mm, 1)
	})
	t.Run("ukjent identitet, e-post A, auto_link=1 kobler", func(t *testing.T) {
		f := newResolveFx(t)
		a := f.user(t, "a@x.no")
		f.identity(t, a.ID, "annen")
		u, out, err := f.r.resolve(ctx, gext("s2", " A@X.no"), linkPolicy{AutoLink: true}, resolveMeta{})
		require.NoError(t, err)
		require.Equal(t, a.ID, u.ID)
		require.Equal(t, outcomeLinked, out)
		ev := f.auditTypes(t, "identity_linked")
		require.Len(t, ev, 1)
		require.Equal(t, "provider=google issuer="+testIssuer+" transition=0", *ev[0].Details)
		require.NotContains(t, *ev[0].Details, "s2")
	})
	t.Run("auto_link=0 og A uten identitet kobler som overgang", func(t *testing.T) {
		f := newResolveFx(t)
		a := f.user(t, "a@x.no")
		_, out, err := f.r.resolve(ctx, gext("s3", "a@x.no"), linkPolicy{}, resolveMeta{})
		require.NoError(t, err)
		require.Equal(t, outcomeLinked, out)
		ev := f.auditTypes(t, "identity_linked")
		require.Len(t, ev, 1)
		require.Contains(t, *ev[0].Details, "transition=1")
		ids, err := f.q.ListIdentitiesByUser(ctx, a.ID)
		require.NoError(t, err)
		require.Len(t, ids, 1)
	})
	t.Run("auto_link=0 og A med identitet gir errLinkDenied", func(t *testing.T) {
		f := newResolveFx(t)
		a := f.user(t, "a@x.no")
		f.identity(t, a.ID, "eldre")
		_, _, err := f.r.resolve(ctx, gext("ny", "a@x.no"), linkPolicy{}, resolveMeta{})
		require.ErrorIs(t, err, errLinkDenied)
		ids, _ := f.q.ListIdentitiesByUser(ctx, a.ID)
		require.Len(t, ids, 1)
		require.Len(t, f.auditTypes(t, "identity_link_denied"), 1)
	})
	t.Run("ingen bruker og auto_register=1 registrerer bruker og identitet", func(t *testing.T) {
		f := newResolveFx(t)
		u, out, err := f.r.resolve(ctx, gext("s5", "ny@x.no"), linkPolicy{AutoRegister: true, DefaultRole: "r", DefaultOrg: "o"}, resolveMeta{})
		require.NoError(t, err)
		require.Equal(t, outcomeRegistered, out)
		require.NotEmpty(t, u.PublicID)
		require.Equal(t, "r", u.Roles)
		ids, _ := f.q.ListIdentitiesByUser(ctx, u.ID)
		require.Len(t, ids, 1)
	})
	t.Run("ingen bruker og auto_register=0 gir errNoAccount", func(t *testing.T) {
		f := newResolveFx(t)
		_, _, err := f.r.resolve(ctx, gext("s6", "ny@x.no"), linkPolicy{AutoLink: true}, resolveMeta{})
		require.ErrorIs(t, err, errNoAccount)
	})
	t.Run("auto_link=0 og ingen bruker registrerer likevel", func(t *testing.T) {
		f := newResolveFx(t)
		_, out, err := f.r.resolve(ctx, gext("s7", "ny@x.no"), linkPolicy{AutoRegister: true}, resolveMeta{})
		require.NoError(t, err)
		require.Equal(t, outcomeRegistered, out)
	})
}

func TestResolve_InactiveUser(t *testing.T) {
	ctx := context.Background()
	f := newResolveFx(t)
	a := f.user(t, "a@x.no")
	f.identity(t, a.ID, "s1")
	now := t0
	_, err := f.q.DeactivateUser(ctx, gen.DeactivateUserParams{DeactivatedAt: &now, ID: a.ID})
	require.NoError(t, err)
	before, _ := f.q.CountUsers(ctx)

	_, _, err = f.r.resolve(ctx, gext("s1", "a@x.no"), linkPolicy{AutoLink: true, AutoRegister: true}, resolveMeta{})
	require.ErrorIs(t, err, errUserInactive)
	after, _ := f.q.CountUsers(ctx)
	require.Equal(t, before, after, "ingen ny bruker")

	// Deaktivert konto uten identitet: e-posten er opptatt, så registrering gir konflikt.
	b := f.user(t, "b@x.no")
	_, err = f.q.DeactivateUser(ctx, gen.DeactivateUserParams{DeactivatedAt: &now, ID: b.ID})
	require.NoError(t, err)
	_, _, err = f.r.resolve(ctx, gext("s9", "b@x.no"), linkPolicy{AutoLink: true, AutoRegister: true}, resolveMeta{})
	require.ErrorIs(t, err, errUserConflict)
}

func TestResolve_TechnicalErrorIsNotConflict(t *testing.T) {
	f := newResolveFx(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := f.r.resolve(ctx, gext("s", "ny@x.no"), linkPolicy{AutoRegister: true}, resolveMeta{})
	require.Error(t, err)
	require.NotErrorIs(t, err, errUserConflict)
	require.NotErrorIs(t, err, errNoAccount)
}

func TestResolve_ConcurrentFirstLogin(t *testing.T) {
	ctx := context.Background()
	f := newResolveFx(t)
	const n = 8
	ids := make([]int64, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			u, _, err := f.r.resolve(ctx, gext("samtidig", "ny@x.no"), linkPolicy{AutoLink: true, AutoRegister: true}, resolveMeta{})
			ids[i], errs[i] = u.ID, err
		}(i)
	}
	close(start)
	wg.Wait()
	for i := 0; i < n; i++ {
		require.NoError(t, errs[i])
		require.Equal(t, ids[0], ids[i])
	}
	var idRows, userRows int
	require.NoError(t, f.db.QueryRow("SELECT COUNT(*) FROM user_identities").Scan(&idRows))
	require.NoError(t, f.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userRows))
	require.Equal(t, 1, idRows)
	require.Equal(t, 1, userRows)
}

// Feil i InsertIdentity etter CreateUser skal rulle tilbake brukeren.
func TestResolve_RegisterAtomic(t *testing.T) {
	ctx := context.Background()
	f := newResolveFx(t)
	bad := gext("s", "ny@x.no")
	bad.Provider = "ugyldig" // bryter CHECK på user_identities.provider
	_, _, err := f.r.resolve(ctx, bad, linkPolicy{AutoRegister: true}, resolveMeta{})
	require.Error(t, err)
	_, err = f.q.GetUserByEmail(ctx, "ny@x.no")
	require.Error(t, err, "brukeren skal være rullet tilbake")
}

func TestGoogleIssuerCanonical(t *testing.T) {
	for _, tc := range []struct {
		iss, sub string
		ok       bool
	}{
		{"https://accounts.google.com", "1", true},
		{"accounts.google.com", "1", true},
		{"https://accounts.google.com.evil.no", "1", false},
		{"", "1", false},
		{"https://accounts.google.com", "", false},
		{"https://accounts.google.com", "  ", false},
	} {
		ext, ok := googleIdentity(googleClaims{Iss: tc.iss, Sub: tc.sub}, "a@x.no")
		require.Equal(t, tc.ok, ok, "%q %q", tc.iss, tc.sub)
		if ok {
			require.Equal(t, "https://accounts.google.com", ext.Issuer)
		}
	}
}

// Begge issuer-skrivemåter gir samme identitet, ikke to.
func TestGoogleFinish_IssuerFormsShareIdentity(t *testing.T) {
	f := newAdminFlowFixture(t)
	for _, iss := range []string{"accounts.google.com", "https://accounts.google.com"} {
		w := httptest.NewRecorder()
		f.h.finishCallback(w, httptest.NewRequest(http.MethodGet, "/callback", nil), f.svc, false,
			googleClaims{Sub: "42", Iss: iss, Email: "vanlig@example.com", EmailVerified: true}, "n", "n")
		require.Equal(t, http.StatusFound, w.Code)
	}
	u, err := f.q.GetUserByEmail(context.Background(), "vanlig@example.com")
	require.NoError(t, err)
	ids, err := f.q.ListIdentitiesByUser(context.Background(), u.ID)
	require.NoError(t, err)
	require.Len(t, ids, 1)
	require.Equal(t, "https://accounts.google.com", ids[0].Issuer)
}

func TestGoogleFinish_MissingSubRejected(t *testing.T) {
	f := newAdminFlowFixture(t)
	w := httptest.NewRecorder()
	f.h.finishCallback(w, httptest.NewRequest(http.MethodGet, "/callback", nil), f.svc, false,
		googleClaims{Iss: googleIssuer, Email: "vanlig@example.com", EmailVerified: true}, "n", "n")
	require.Equal(t, "/login?error=login_failed&service=klarsyn", w.Header().Get("Location"))
}

func TestMSClaims_MissingOrInvalidOID(t *testing.T) {
	for name, oid := range map[string]string{"mangler": "", "ikke guid": "abc", "med mellomrom": " " + msTestOID} {
		t.Run(name, func(t *testing.T) {
			f, svc := newMSFixture(t, 1, nil)
			cl := msValid(msOrgTid, msBool(true))
			cl.Oid = oid
			before, _ := f.q.CountUsers(context.Background())
			rr := msFinish(f, svc, cl)
			require.Equal(t, "/login?error=login_failed&service=klarsyn", rr.Header().Get("Location"))
			after, _ := f.q.CountUsers(context.Background())
			require.Equal(t, before, after)
			ev := msAuditEvents(t, f, "microsoft_oidc_rejected", 1)
			require.Contains(t, *ev[0].Details, "reason=missing_oid")
		})
	}
}

func TestMSFinish_OIDIdentityUsesTenantIssuer(t *testing.T) {
	f, svc := newMSFixture(t, 1, nil)
	rr := msFinish(f, svc, msValid(msOrgTid, msBool(true)))
	require.Equal(t, http.StatusFound, rr.Code)
	u, err := f.q.GetUserByEmail(context.Background(), "a@example.com")
	require.NoError(t, err)
	require.NotEmpty(t, u.PublicID)
	ids, err := f.q.ListIdentitiesByUser(context.Background(), u.ID)
	require.NoError(t, err)
	require.Len(t, ids, 1)
	require.Equal(t, "microsoft", ids[0].Provider)
	require.Equal(t, msIss(msOrgTid), ids[0].Issuer)
	require.Equal(t, msTestOID, ids[0].Subject)
}

// K12: Ø og ø er samme adresse etter normalisering, uansett innloggingsvei.
func TestEmailLookup_NonASCII(t *testing.T) {
	require.Equal(t, NormalizeEmail("Ø@x.no"), NormalizeEmail("ø@x.no"))
	f := newAdminFlowFixture(t)
	existing, err := f.q.CreateUser(context.Background(), gen.CreateUserParams{PublicID: token.MustNewPublicID(), Email: NormalizeEmail("ø@x.no"), Roles: "user", CreatedAt: t0})
	require.NoError(t, err)
	w := httptest.NewRecorder()
	f.h.finishCallback(w, httptest.NewRequest(http.MethodGet, "/callback", nil), f.svc, false,
		googleClaims{Sub: "o", Iss: googleIssuer, Email: "Ø@X.no", EmailVerified: true}, "n", "n")
	require.Equal(t, http.StatusFound, w.Code)
	ids, err := f.q.ListIdentitiesByUser(context.Background(), existing.ID)
	require.NoError(t, err)
	require.Len(t, ids, 1)
}

func TestAdminGoogle_UsesResolverAutoLinkOff(t *testing.T) {
	ctx := context.Background()
	f := newAdminFlowFixture(t)
	login := func(sub, email string) string {
		w := httptest.NewRecorder()
		f.h.finishCallback(w, httptest.NewRequest(http.MethodGet, "/callback", nil), f.svc, true,
			googleClaims{Sub: sub, Iss: googleIssuer, Email: email, EmailVerified: true}, "n", "n")
		return w.Header().Get("Location")
	}
	// Admin uten identitet kobles og godkjennes (overgang).
	require.Equal(t, "/admin/users", login("k1", "konge@example.com"))
	u, _ := f.q.GetUserByEmail(ctx, "konge@example.com")
	ids, _ := f.q.ListIdentitiesByUser(ctx, u.ID)
	require.Len(t, ids, 1)
	require.EqualValues(t, 1, ids[0].AdminOk)
	require.Len(t, f.auditEvents(t, "identity_admin_approved", 1), 1)
	// Samme konto igjen: ok. Annen Google-konto med samme e-post: avvist.
	require.Equal(t, "/admin/users", login("k1", "konge@example.com"))
	require.Equal(t, "/admin/login?err=ingen_tilgang", login("k2", "konge@example.com"))
	// Ikke-konge avvises. Resolveren kobler identiteten (koblinger er globale),
	// men admin_ok settes aldri.
	require.Equal(t, "/admin/login?err=ingen_tilgang", login("v1", "vanlig@example.com"))
	vu, _ := f.q.GetUserByEmail(ctx, "vanlig@example.com")
	vids, _ := f.q.ListIdentitiesByUser(ctx, vu.ID)
	require.Len(t, vids, 1)
	require.EqualValues(t, 0, vids[0].AdminOk)
	// Ingen auto-registrering selv om tjenesten har auto_register=1.
	before := f.countFn()
	require.Equal(t, "/admin/login?err=ingen_tilgang", login("n1", "helt-ny@example.com"))
	require.Equal(t, before, f.countFn())
}

// Lars-beslutning (security M1): en identitet koblet via en vanlig tjeneste
// med auto_link=1 er ikke godkjent for admin.
func TestAdminGoogle_OnlyApprovedIdentity(t *testing.T) {
	ctx := context.Background()
	f := newAdminFlowFixture(t)
	admin := func(sub string) string {
		w := httptest.NewRecorder()
		f.h.finishCallback(w, httptest.NewRequest(http.MethodGet, "/callback", nil), f.svc, true,
			googleClaims{Sub: sub, Iss: googleIssuer, Email: "konge@example.com", EmailVerified: true}, "n", "n")
		return w.Header().Get("Location")
	}
	require.Equal(t, "/admin/users", admin("godkjent"))

	// Annen Google-konto kobles via vanlig tjeneste med auto_link=1.
	svc := *f.svc
	svc.AutoLink = 1
	w := httptest.NewRecorder()
	f.h.finishCallback(w, httptest.NewRequest(http.MethodGet, "/callback", nil), &svc, false,
		googleClaims{Sub: "gammel", Iss: googleIssuer, Email: "konge@example.com", EmailVerified: true}, "n", "n")
	require.Equal(t, http.StatusFound, w.Code)
	u, _ := f.q.GetUserByEmail(ctx, "konge@example.com")
	ids, _ := f.q.ListIdentitiesByUser(ctx, u.ID)
	require.Len(t, ids, 2)

	// Den koblede avvises mot admin, den godkjente fungerer fortsatt.
	require.Equal(t, "/admin/login?err=ingen_tilgang", admin("gammel"))
	ev := f.auditEvents(t, "identity_link_denied", 1)
	require.Contains(t, *ev[len(ev)-1].Details, "reason=not_admin_identity")
	require.Equal(t, "/admin/users", admin("godkjent"))
	ids, _ = f.q.ListIdentitiesByUser(ctx, u.ID)
	approved := 0
	for _, i := range ids {
		approved += int(i.AdminOk)
	}
	require.Equal(t, 1, approved)
}

// Betinget UPDATE: ulike identiteter for samme bruker kan ikke begge bli godkjent.
func TestApproveAdminIdentity_AtMostOne(t *testing.T) {
	ctx := context.Background()
	f := newResolveFx(t)
	u := f.user(t, "k@x.no")
	var idns []int64
	for _, sub := range []string{"a", "b", "c", "d"} {
		f.identity(t, u.ID, sub)
	}
	ids, _ := f.q.ListIdentitiesByUser(ctx, u.ID)
	for _, i := range ids {
		idns = append(idns, i.ID)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := f.q.ApproveAdminIdentity(ctx, gen.ApproveAdminIdentityParams{ID: idns[i%len(idns)], UserID: u.ID, UserID_2: u.ID})
			require.NoError(t, err)
		}(i)
	}
	close(start)
	wg.Wait()
	var n int
	require.NoError(t, f.db.QueryRow("SELECT COUNT(*) FROM user_identities WHERE admin_ok = 1").Scan(&n))
	require.Equal(t, 1, n)
}

// auto_link=0: to ulike kontoer samtidig mot samme bruker, nøyaktig én kobles.
func TestResolve_ConcurrentLinkDifferentIdentities_AutoLinkOff(t *testing.T) {
	ctx := context.Background()
	f := newResolveFx(t)
	u := f.user(t, "a@x.no")
	const n = 8
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, _, errs[i] = f.r.resolve(ctx, gext("konto-"+string(rune('a'+i)), "a@x.no"), linkPolicy{}, resolveMeta{})
		}(i)
	}
	close(start)
	wg.Wait()
	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
		} else {
			require.ErrorIs(t, err, errLinkDenied)
		}
	}
	require.Equal(t, 1, ok)
	ids, _ := f.q.ListIdentitiesByUser(ctx, u.ID)
	require.Len(t, ids, 1)
}

// Taperens sti (0 rader fra INSERT) når samme identitet kobles samtidig.
func TestResolve_ConcurrentLinkSameIdentity(t *testing.T) {
	for _, autoLink := range []bool{true, false} {
		ctx := context.Background()
		f := newResolveFx(t)
		u := f.user(t, "a@x.no")
		const n = 8
		errs := make([]error, n)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				got, _, err := f.r.resolve(ctx, gext("samme", "a@x.no"), linkPolicy{AutoLink: autoLink}, resolveMeta{})
				errs[i] = err
				if err == nil {
					require.Equal(t, u.ID, got.ID)
				}
			}(i)
		}
		close(start)
		wg.Wait()
		for _, err := range errs {
			require.NoError(t, err)
		}
		ids, _ := f.q.ListIdentitiesByUser(ctx, u.ID)
		require.Len(t, ids, 1)
	}
}

// Avviket logges bare når leverandørens e-post er endret siden sist.
func TestResolve_EmailMismatchAuditedOnlyOnChange(t *testing.T) {
	ctx := context.Background()
	f := newResolveFx(t)
	a := f.user(t, "a@x.no")
	f.identity(t, a.ID, "s1")
	for i := 0; i < 3; i++ {
		_, _, err := f.r.resolve(ctx, gext("s1", "b@x.no"), linkPolicy{}, resolveMeta{})
		require.NoError(t, err)
	}
	ev := f.auditTypes(t, "identity_email_mismatch")
	time.Sleep(200 * time.Millisecond)
	ev = f.auditTypes(t, "identity_email_mismatch")
	require.Len(t, ev, 1)
	require.EqualValues(t, 1, ev[0].Success)
	require.NotContains(t, *ev[0].Details, "@")
}

func TestGoogleFinish_EmptyEmailRejected(t *testing.T) {
	f := newAdminFlowFixture(t)
	before := f.countFn()
	w := httptest.NewRecorder()
	f.h.finishCallback(w, httptest.NewRequest(http.MethodGet, "/callback", nil), f.svc, false,
		googleClaims{Sub: "x", Iss: googleIssuer, Email: "  ", EmailVerified: true}, "n", "n")
	require.Equal(t, "/login?error=login_failed&service=klarsyn", w.Header().Get("Location"))
	require.Equal(t, before, f.countFn())
}

func TestMSFinish_LinkDeniedInactiveAndLowercaseSubject(t *testing.T) {
	ctx := context.Background()
	// to ulike oid, samme e-post, auto_link=0: andre avvises
	f, svc := newMSFixture(t, 0, nil)
	svc.AutoLink = 0
	cl := msValid(msOrgTid, msBool(true))
	cl.Email = "kjent@example.com"
	cl.Oid = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
	require.Equal(t, http.StatusFound, msFinish(f, svc, cl).Code)
	u, _ := f.q.GetUserByEmail(ctx, "kjent@example.com")
	ids, _ := f.q.ListIdentitiesByUser(ctx, u.ID)
	require.Len(t, ids, 1)
	require.Equal(t, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", ids[0].Subject)
	// samme oid i annen skrivemåte er samme identitet
	cl.Oid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	require.Equal(t, http.StatusFound, msFinish(f, svc, cl).Code)

	cl.Oid = "11111111-bbbb-cccc-dddd-eeeeeeeeeeee"
	rr := msFinish(f, svc, cl)
	require.Equal(t, "/login?error=account_not_linked&service=klarsyn", rr.Header().Get("Location"))
	ids, _ = f.q.ListIdentitiesByUser(ctx, u.ID)
	require.Len(t, ids, 1)

	// auto_link=1: to oid gir to identiteter
	svc.AutoLink = 1
	require.Equal(t, http.StatusFound, msFinish(f, svc, cl).Code)
	ids, _ = f.q.ListIdentitiesByUser(ctx, u.ID)
	require.Len(t, ids, 2)

	// deaktivert bruker bak kjent identitet: access_denied, ingen token
	now := t0
	_, err := f.q.DeactivateUser(ctx, gen.DeactivateUserParams{DeactivatedAt: &now, ID: u.ID})
	require.NoError(t, err)
	rr = msFinish(f, svc, cl)
	require.Equal(t, "/login?error=access_denied&service=klarsyn", rr.Header().Get("Location"))
	require.Empty(t, rr.Result().Cookies())
}

func TestLoginPage_AccountNotLinkedText(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)
	render := func(locale string, magic int64) string {
		data := testPageData(t, "light", locale, "/login?service=test")
		data.Error = "account_not_linked"
		data.Service.AuthMagicLink = magic
		var out strings.Builder
		require.NoError(t, tmpl.ExecuteTemplate(&out, "login.html", data))
		return out.String()
	}
	for locale, want := range map[string][2]string{
		"nb": {"Logg inn med kontoen du brukte sist.", "sist, eller med e-postlenke."},
		"en": {"account you used last time.", "last time, or with an email link."},
		"de": {"zuletzt verwendeten Konto an.", "oder mit einem E-Mail-Link an."},
	} {
		without, with := render(locale, 0), render(locale, 1)
		require.Contains(t, without, want[0], locale)
		require.NotContains(t, without, want[1], locale)
		require.Contains(t, with, want[1], locale)
	}
}

func TestCallback_AccountNotLinked(t *testing.T) {
	ctx := context.Background()
	f := newAdminFlowFixture(t)
	svc := *f.svc
	svc.AutoLink = 0
	u, err := f.q.GetUserByEmail(ctx, "vanlig@example.com")
	require.NoError(t, err)
	_, err = f.q.InsertIdentity(ctx, gen.InsertIdentityParams{UserID: u.ID, Provider: "google", Issuer: testIssuer, Subject: "eldre", CreatedAt: t0})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	f.h.finishCallback(w, httptest.NewRequest(http.MethodGet, "/callback", nil), &svc, false,
		googleClaims{Sub: "ny", Iss: googleIssuer, Email: "vanlig@example.com", EmailVerified: true}, "n", "n")
	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Equal(t, "/login?error=account_not_linked&service=klarsyn", w.Header().Get("Location"))
	require.Empty(t, w.Result().Cookies())
	require.Len(t, f.auditEvents(t, "identity_link_denied", 1), 1)
}
