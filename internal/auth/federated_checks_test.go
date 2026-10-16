package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
)

// Sikkerhetssjekkene i den fødererte stien (014 AN §6) som ikke hadde egen
// test før Google og Microsoft ble flyttet over på felles kode.

// fcCountingTokenEndpoint er en lokal tokenserver som teller kall, slik at
// testene kan vise at ingen kodeutveksling skjedde.
func fcCountingTokenEndpoint(t *testing.T) (*oauth2.Endpoint, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "feil", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return &oauth2.Endpoint{AuthURL: srv.URL + "/auth", TokenURL: srv.URL + "/token"}, &hits
}

func fcCallbackReq(path, cookieName, state, host string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path+"?code=c&state="+url.QueryEscape(state), nil)
	if host != "" {
		req.Host = host
	}
	req.AddCookie(&http.Cookie{Name: cookieName, Value: state})
	return req
}

func fcDetails(t *testing.T, ev gen.AuditEvent) string {
	t.Helper()
	require.NotNil(t, ev.Details)
	return *ev.Details
}

// S6: en admin-state på /ms-callback avvises før noe kall mot Microsoft, selv
// om sømmen ville gitt gyldige claims.
func TestMSCallback_AdminState_RejectedBeforeFetchClaims(t *testing.T) {
	f, _ := newMSFixture(t, 0, nil)
	var calls atomic.Int32
	good := msValid(msOrgTid, msBool(true))
	good.Email = "kjent@example.com"
	f.h.fetchClaims = func(context.Context, *oauth2.Config, string) (msClaims, error) {
		calls.Add(1)
		return good, nil
	}
	st := signAdminState(f.h.cfg.OIDCStateSecret, "klarsyn", msTestNon)
	w := httptest.NewRecorder()
	f.h.HandleCallback(w, fcCallbackReq("/ms-callback", "ms_state", st, ""))

	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Equal(t, "/login?error=login_failed", w.Header().Get("Location"))
	require.Equal(t, int32(0), calls.Load(), "fetchClaims skal aldri kalles")
	require.Empty(t, w.Result().Cookies())
	require.NotContains(t, w.Header().Get("Location"), "/dispatch")
	ev := drainAudit(t, f.q, f.h.aud)
	require.Empty(t, lbOfType(ev, "microsoft_oidc_login"))
	require.Empty(t, lbOfType(ev, "microsoft_oidc_rejected"), "admin-state auditeres ikke")
}

// S7: en tjeneste som er deaktivert mens staten levde, avvises uten
// kodeutveksling.
func TestGoogleCallback_UnknownService_PlainBranch(t *testing.T) {
	f := newAdminFlowFixture(t)
	_, hits := fcTokenEndpointFor(t, f)
	st := SignState(f.cfg.OIDCStateSecret, "borte", "n")
	w := httptest.NewRecorder()
	f.h.HandleCallback(w, fcCallbackReq("/callback", "oidc_state", st, "klarsyn.net"))

	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Equal(t, "/login?error=login_failed&service=borte", w.Header().Get("Location"))
	requireRedirectBodyOnly(t, w)
	require.Equal(t, int32(0), hits.Load(), "ingen kodeutveksling")
	ev := lbOfType(drainAudit(t, f.q, f.h.aud), "google_oidc_rejected")
	require.Len(t, ev, 1)
	require.Equal(t, "reason=unknown_service", fcDetails(t, ev[0]))
	require.Equal(t, int64(0), ev[0].Success)
	require.NotNil(t, ev[0].ServiceID)
	require.Equal(t, "borte", *ev[0].ServiceID)
}

func fcTokenEndpointFor(t *testing.T, f *adminFlowFixture) (*oauth2.Endpoint, *atomic.Int32) {
	t.Helper()
	ep, hits := fcCountingTokenEndpoint(t)
	f.h.endpoint = ep
	return ep, hits
}

func TestGoogleCallback_UnknownService_AdminBranch(t *testing.T) {
	f := newAdminFlowFixture(t)
	_, hits := fcTokenEndpointFor(t, f)
	st := signAdminState(f.cfg.OIDCStateSecret, "borte", "n")
	w := httptest.NewRecorder()
	f.h.HandleCallback(w, fcCallbackReq("/callback", "oidc_state", st, "klarsyn.net"))

	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Equal(t, "/admin/login?err=ingen_tilgang", w.Header().Get("Location"))
	require.Nil(t, cookieNamed(w, "admin_token"))
	require.Equal(t, int32(0), hits.Load(), "ingen kodeutveksling")
	all := drainAudit(t, f.q, f.h.aud)
	ev := lbOfType(all, "admin_google_login")
	require.Len(t, ev, 1)
	require.Equal(t, int64(0), ev[0].Success)
	require.Equal(t, "reason=unknown_service", fcDetails(t, ev[0]))
	require.Empty(t, lbOfType(all, "google_oidc_rejected"))
}

func TestMSCallback_UnknownService(t *testing.T) {
	f, _ := newMSFixture(t, 0, nil)
	var calls atomic.Int32
	f.h.fetchClaims = func(context.Context, *oauth2.Config, string) (msClaims, error) {
		calls.Add(1)
		return msClaims{}, errors.New("skal ikke kalles")
	}
	st := SignState(f.h.cfg.OIDCStateSecret, "borte", msTestNon)
	w := httptest.NewRecorder()
	f.h.HandleCallback(w, fcCallbackReq("/ms-callback", "ms_state", st, ""))

	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Equal(t, "/login?error=login_failed", w.Header().Get("Location"), "uten &service= (D3)")
	require.Equal(t, int32(0), calls.Load(), "ingen kodeutveksling")
	require.Empty(t, w.Result().Cookies())
	ev := lbOfType(drainAudit(t, f.q, f.h.aud), "microsoft_oidc_rejected")
	require.Len(t, ev, 1)
	require.Equal(t, "reason=unknown_service", fcDetails(t, ev[0]))
	require.NotNil(t, ev[0].ServiceID)
	require.Equal(t, "borte", *ev[0].ServiceID)
}

// S10: tom e-post i vanlig gren auditeres med egen årsak.
func TestGoogleFinish_EmptyEmail_AuditsEmailMissing(t *testing.T) {
	f := newAdminFlowFixture(t)
	before := f.countFn()
	w := httptest.NewRecorder()
	f.h.finishCallback(w, httptest.NewRequest(http.MethodGet, "/callback", nil), f.svc, false,
		googleClaims{Sub: "sub-1", Iss: googleIssuer, Email: "  ", EmailVerified: true}, "n", "n")

	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Equal(t, "/login?error=login_failed&service=klarsyn", w.Header().Get("Location"))
	require.Empty(t, w.Result().Cookies())
	require.Equal(t, before, f.countFn())
	ev := lbOfType(drainAudit(t, f.q, f.h.aud), "google_oidc_rejected")
	require.Len(t, ev, 1)
	require.Equal(t, "reason=email_missing", fcDetails(t, ev[0]))
}

// S13: en fremmed issuer gir ingen identitet og ingen bruker.
func TestGoogleFinish_ForeignIssuer_MissingSub(t *testing.T) {
	f := newAdminFlowFixture(t)
	before := f.countFn()
	for _, iss := range []string{"https://evil.example", "", "https://accounts.google.com/"} {
		w := httptest.NewRecorder()
		f.h.finishCallback(w, httptest.NewRequest(http.MethodGet, "/callback", nil), f.svc, false,
			googleClaims{Sub: "sub-1", Iss: iss, Email: "ny@example.com", EmailVerified: true}, "n", "n")
		require.Equal(t, http.StatusSeeOther, w.Code, iss)
		require.Equal(t, "/login?error=login_failed&service=klarsyn", w.Header().Get("Location"), iss)
		require.Empty(t, w.Result().Cookies(), iss)
	}
	require.Equal(t, before, f.countFn(), "ingen bruker opprettet")
	var idents int
	require.NoError(t, f.h.sqlDB.QueryRow("SELECT COUNT(*) FROM user_identities").Scan(&idents))
	require.Equal(t, 0, idents)
	ev := lbOfType(drainAudit(t, f.q, f.h.aud), "google_oidc_rejected")
	require.Len(t, ev, 3)
	for _, e := range ev {
		require.Equal(t, "reason=missing_sub", fcDetails(t, e))
	}
}

// S14: tid med store heksbokstaver gir issuer med små bokstaver, ellers kunne
// samme tenant fått to identiteter.
func TestMSFinish_UppercaseTid_LowercaseIssuer(t *testing.T) {
	const upperTid = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
	f, svc := newMSFixture(t, 0, nil)
	cl := msValid(upperTid, msBool(true))
	cl.Email = "kjent@example.com"
	require.Equal(t, msIss(upperTid), cl.Iss, "iss har samme skrivemåte som tid")
	rr := msFinish(f, svc, cl)

	require.Equal(t, http.StatusFound, rr.Code)
	require.True(t, strings.HasPrefix(rr.Header().Get("Location"), "/dispatch?"))
	var issuer string
	require.NoError(t, f.h.resolver.db.QueryRow("SELECT issuer FROM user_identities").Scan(&issuer))
	require.Equal(t, "https://login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/v2.0", issuer)
}

// S17: deaktivert bruker bak en kjent identitet gir access_denied og audit med
// årsak, uten cookies.
func TestGoogleFinish_InactiveUserBehindKnownIdentity(t *testing.T) {
	f := newAdminFlowFixture(t)
	ctx := context.Background()
	u, err := f.q.GetUserByEmail(ctx, "vanlig@example.com")
	require.NoError(t, err)
	now := time.Now().UTC().Format(time.RFC3339)
	em := u.Email
	_, err = f.q.InsertIdentity(ctx, gen.InsertIdentityParams{UserID: u.ID, Provider: "google", Issuer: googleIssuer, Subject: "sub-inaktiv", Email: &em, CreatedAt: now, LastUsedAt: &now})
	require.NoError(t, err)
	_, err = f.q.DeactivateUser(ctx, gen.DeactivateUserParams{DeactivatedAt: &now, ID: u.ID})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	f.h.finishCallback(w, httptest.NewRequest(http.MethodGet, "/callback", nil), f.svc, false,
		googleClaims{Sub: "sub-inaktiv", Iss: googleIssuer, Email: "Vanlig@Example.com", EmailVerified: true}, "n", "n")

	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Equal(t, "/login?error=access_denied&service=klarsyn", w.Header().Get("Location"))
	require.Empty(t, w.Result().Cookies())
	ev := lbOfType(drainAudit(t, f.q, f.h.aud), "google_oidc_rejected")
	require.Len(t, ev, 1)
	require.Equal(t, "reason=user_inactive", fcDetails(t, ev[0]))
	require.NotNil(t, ev[0].Email)
	require.Equal(t, "vanlig@example.com", *ev[0].Email)
}

func TestMSFinish_InactiveUserBehindKnownIdentity(t *testing.T) {
	f, svc := newMSFixture(t, 0, nil)
	ctx := context.Background()
	u, err := f.q.GetUserByEmail(ctx, "kjent@example.com")
	require.NoError(t, err)
	now := time.Now().UTC().Format(time.RFC3339)
	em := u.Email
	_, err = f.q.InsertIdentity(ctx, gen.InsertIdentityParams{UserID: u.ID, Provider: "microsoft", Issuer: "https://login.microsoftonline.com/" + msOrgTid + "/v2.0", Subject: msTestOID, Email: &em, CreatedAt: now, LastUsedAt: &now})
	require.NoError(t, err)
	_, err = f.q.DeactivateUser(ctx, gen.DeactivateUserParams{DeactivatedAt: &now, ID: u.ID})
	require.NoError(t, err)

	cl := msValid(msOrgTid, msBool(true))
	cl.Email = " Kjent@Example.com"
	rr := msFinish(f, svc, cl)

	require.Equal(t, http.StatusSeeOther, rr.Code)
	require.Equal(t, "/login?error=access_denied&service=klarsyn", rr.Header().Get("Location"))
	require.Empty(t, rr.Result().Cookies())
	ev := lbOfType(drainAudit(t, f.q, f.h.aud), "microsoft_oidc_rejected")
	require.Len(t, ev, 1)
	require.Equal(t, "reason=user_inactive", fcDetails(t, ev[0]))
	require.NotNil(t, ev[0].Email)
	require.Equal(t, "kjent@example.com", *ev[0].Email)
}

// fcSecondService er en annen tenants tjeneste med egen auth_host.
func fcSecondService() gen.Service {
	host := "y.example"
	return gen.Service{ID: "ytjeneste", Domain: "y.test", AuthHost: &host, CallbackUrl: "https://y.test/cb", AuthGoogle: 1, AuthMicrosoft: 1, Active: 1}
}

// S21: tjenesten kommer fra den signerte staten, ikke fra Host. En forespørsel
// med en annen tjenestes auth_host skal fortsatt ende hos statens tjeneste.
func TestGoogleCallback_ServiceFromStateNotHost(t *testing.T) {
	f := newAdminFlowFixture(t)
	f.h.reg = service.NewRegistryForTest([]gen.Service{*f.svc, fcSecondService()})
	f.h.fetchClaims = func(context.Context, *oauth2.Config, string, string) (googleClaims, string, string) {
		return googleClaims{Sub: "sub-1", Iss: googleIssuer, Email: "konge@example.com", EmailVerified: true}, "state-nonce", ""
	}
	st := SignState(f.cfg.OIDCStateSecret, "klarsyn", "state-nonce")
	w := httptest.NewRecorder()
	f.h.HandleCallback(w, fcCallbackReq("/callback", "oidc_state", st, "y.example"))

	require.Equal(t, http.StatusFound, w.Code)
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/dispatch", loc.Path)
	require.Equal(t, "klarsyn", loc.Query().Get("service"))
}

func TestMSCallback_ServiceFromStateNotHost(t *testing.T) {
	f, svc := newMSFixture(t, 0, nil)
	f.h.reg = service.NewRegistryForTest([]gen.Service{*svc, fcSecondService()})
	good := msValid(msOrgTid, msBool(true))
	good.Email = "kjent@example.com"
	good.Nonce = "state-nonce"
	f.h.fetchClaims = func(context.Context, *oauth2.Config, string) (msClaims, error) { return good, nil }
	st := SignState(f.h.cfg.OIDCStateSecret, "klarsyn", "state-nonce")
	w := httptest.NewRecorder()
	f.h.HandleCallback(w, fcCallbackReq("/ms-callback", "ms_state", st, "y.example"))

	require.Equal(t, http.StatusFound, w.Code)
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/dispatch", loc.Path)
	require.Equal(t, "klarsyn", loc.Query().Get("service"))
}

// S22: init mot en tjeneste der metoden er av gir 403 uten state-cookie og
// uten redirect til leverandøren.
func TestGoogleInit_MethodOff_Forbidden(t *testing.T) {
	f := newAdminFlowFixture(t)
	inits := map[string]func(http.ResponseWriter, *http.Request){
		"oidc-login":        f.h.InitiateLogin,
		"admin/google-init": f.h.InitiateAdminLogin,
	}
	call := func(name string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/"+name, nil)
		req.Host = "klarsyn.net"
		w := httptest.NewRecorder()
		inits[name](w, req)
		return w
	}
	for name := range inits {
		w := call(name)
		require.Equal(t, http.StatusFound, w.Code, "kontroll: "+name+" er på")
		require.NotNil(t, cookieNamed(w, "oidc_state"))
	}
	off := *f.svc
	off.AuthGoogle = 0
	f.h.reg = service.NewRegistryForTest([]gen.Service{off})
	for name := range inits {
		t.Run(name, func(t *testing.T) {
			w := call(name)
			require.Equal(t, http.StatusForbidden, w.Code)
			require.Empty(t, w.Header().Get("Location"))
			require.Empty(t, w.Result().Cookies())
		})
	}
}

func TestMSInit_MethodOff_Forbidden(t *testing.T) {
	f, svc := newMSFixture(t, 0, nil)
	call := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/ms-oidc-login", nil)
		req.Host = "klarsyn.net"
		w := httptest.NewRecorder()
		f.h.InitiateLogin(w, req)
		return w
	}
	w := call()
	require.Equal(t, http.StatusFound, w.Code, "kontroll: metoden er på")
	require.NotNil(t, cookieNamed(w, "ms_state"))

	off := *svc
	off.AuthMicrosoft = 0
	f.h.reg = service.NewRegistryForTest([]gen.Service{off})
	w = call()
	require.Equal(t, http.StatusForbidden, w.Code)
	require.Empty(t, w.Header().Get("Location"))
	require.Empty(t, w.Result().Cookies())
}

// D2-lås: i dag auditeres ikke en feilet kodeutveksling hos Microsoft. F3
// snur forventningen til reason=code_exchange.
func TestMSCallback_ExchangeFailure_NotAudited(t *testing.T) {
	f, _ := newMSFixture(t, 0, nil)
	f.h.fetchClaims = func(context.Context, *oauth2.Config, string) (msClaims, error) {
		return msClaims{}, errors.New("kodeutveksling: boom")
	}
	w := httptest.NewRecorder()
	f.h.HandleCallback(w, msStateCookieReq(t, f, "n"))

	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Equal(t, "/login?error=login_failed&service=klarsyn", w.Header().Get("Location"))
	requireRedirectBodyOnly(t, w)
	require.Empty(t, lbOfType(drainAudit(t, f.q, f.h.aud), "microsoft_oidc_rejected"))
}

// S8: Google-callbacken sammenligner nonce i id_token med nonce fra den
// signerte staten. Sømmen får ikke statens nonce, så testen viser at
// HandleCallback sender den videre selv.
func TestGoogleCallback_ComparesNonceFromSignedState(t *testing.T) {
	for _, admin := range []bool{false, true} {
		name := "vanlig"
		if admin {
			name = "admin"
		}
		t.Run(name, func(t *testing.T) {
			f := newAdminFlowFixture(t)
			var gotCode string
			tokenNonce := "state-nonce"
			f.h.fetchClaims = func(_ context.Context, _ *oauth2.Config, _, code string) (googleClaims, string, string) {
				gotCode = code
				return googleClaims{Sub: "sub-1", Iss: googleIssuer, Email: "konge@example.com", EmailVerified: true}, tokenNonce, ""
			}
			sign := SignState
			if admin {
				sign = signAdminState
			}
			st := sign(f.cfg.OIDCStateSecret, "klarsyn", "state-nonce")

			w := httptest.NewRecorder()
			f.h.HandleCallback(w, fcCallbackReq("/callback", "oidc_state", st, "klarsyn.net"))
			require.Equal(t, "c", gotCode)
			if admin {
				require.Equal(t, http.StatusSeeOther, w.Code)
				require.Equal(t, "/admin/users", w.Header().Get("Location"))
			} else {
				require.Equal(t, http.StatusFound, w.Code)
				require.True(t, strings.HasPrefix(w.Header().Get("Location"), "/dispatch?"), w.Header().Get("Location"))
			}

			tokenNonce = "annen-nonce"
			w = httptest.NewRecorder()
			f.h.HandleCallback(w, fcCallbackReq("/callback", "oidc_state", st, "klarsyn.net"))
			if admin {
				require.Equal(t, "/admin/login?err=ingen_tilgang", w.Header().Get("Location"))
				require.Nil(t, cookieNamed(w, "admin_token"))
			} else {
				require.Equal(t, http.StatusSeeOther, w.Code)
				require.Equal(t, "/login?error=login_failed&service=klarsyn", w.Header().Get("Location"))
				require.Nil(t, cookieNamed(w, "refresh_token"))
			}
			all := drainAudit(t, f.q, f.h.aud)
			if admin {
				fails := lbOfType(all, "admin_google_login")
				var failed []gen.AuditEvent
				for _, e := range fails {
					if e.Success == 0 {
						failed = append(failed, e)
					}
				}
				require.Len(t, failed, 1)
				require.Equal(t, "reason=nonce", fcDetails(t, failed[0]))
				return
			}
			ev := lbOfType(all, "google_oidc_rejected")
			require.Len(t, ev, 1)
			require.Equal(t, "reason=nonce", fcDetails(t, ev[0]))
		})
	}
}

// Sømmens årsakskoder havner uendret i audit, også for admin-state.
func TestGoogleCallback_SeamReasonGoesToAudit(t *testing.T) {
	for _, admin := range []bool{false, true} {
		for _, reason := range []string{"code_exchange", "discovery", "id_token", "claims"} {
			name := reason
			if admin {
				name = "admin " + reason
			}
			t.Run(name, func(t *testing.T) {
				f := newAdminFlowFixture(t)
				f.h.fetchClaims = func(context.Context, *oauth2.Config, string, string) (googleClaims, string, string) {
					return googleClaims{}, "", reason
				}
				sign := SignState
				if admin {
					sign = signAdminState
				}
				st := sign(f.cfg.OIDCStateSecret, "klarsyn", "n")
				w := httptest.NewRecorder()
				f.h.HandleCallback(w, fcCallbackReq("/callback", "oidc_state", st, "klarsyn.net"))
				all := drainAudit(t, f.q, f.h.aud)
				if admin {
					require.Equal(t, "/admin/login?err=ingen_tilgang", w.Header().Get("Location"))
					ev := lbOfType(all, "admin_google_login")
					require.Len(t, ev, 1)
					require.Equal(t, int64(0), ev[0].Success)
					require.Equal(t, "reason="+reason, fcDetails(t, ev[0]))
					return
				}
				require.Equal(t, "/login?error=login_failed&service=klarsyn", w.Header().Get("Location"))
				ev := lbOfType(all, "google_oidc_rejected")
				require.Len(t, ev, 1)
				require.Equal(t, "reason="+reason, fcDetails(t, ev[0]))
			})
		}
	}
}

// S1: vellykket admin-innlogging rydder oidc_state. Går via HandleCallback og
// sømmen, så testen tåler at ryddingen flyttes til felles kode.
func TestGoogleFinish_AdminSuccess_ClearsStateCookie(t *testing.T) {
	f := newAdminFlowFixture(t)
	f.h.fetchClaims = func(context.Context, *oauth2.Config, string, string) (googleClaims, string, string) {
		return googleClaims{Sub: "sub-1", Iss: googleIssuer, Email: "konge@example.com", EmailVerified: true}, "state-nonce", ""
	}
	st := signAdminState(f.cfg.OIDCStateSecret, "klarsyn", "state-nonce")
	w := httptest.NewRecorder()
	f.h.HandleCallback(w, fcCallbackReq("/callback", "oidc_state", st, "klarsyn.net"))
	require.Equal(t, "/admin/users", w.Header().Get("Location"))
	sc := cookieNamed(w, "oidc_state")
	require.NotNil(t, sc)
	require.Less(t, sc.MaxAge, 0)
}

// Test-T1: cookie og state-param er hver for seg gyldig signert, men ulike.
func TestMSCallback_CookieAndParamDiffer_Rejected(t *testing.T) {
	f, _ := newMSFixture(t, 0, nil)
	var calls atomic.Int32
	good := msValid(msOrgTid, msBool(true))
	good.Email = "kjent@example.com"
	f.h.fetchClaims = func(context.Context, *oauth2.Config, string) (msClaims, error) {
		calls.Add(1)
		return good, nil
	}
	secret := f.h.cfg.OIDCStateSecret
	cookieState := SignState(secret, "klarsyn", msTestNon)
	paramState := SignState(secret, "klarsyn", "annen-nonce")
	require.NotEqual(t, cookieState, paramState)
	req := httptest.NewRequest(http.MethodGet, "/ms-callback?code=c&state="+url.QueryEscape(paramState), nil)
	req.AddCookie(&http.Cookie{Name: "ms_state", Value: cookieState})
	w := httptest.NewRecorder()
	f.h.HandleCallback(w, req)

	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Equal(t, "/login?error=login_failed", w.Header().Get("Location"))
	require.Equal(t, int32(0), calls.Load())
	require.Empty(t, w.Result().Cookies())
}

// S31 (Google): sømmen får tjenestens egne credentials, ikke de globale.
func TestGoogleCallback_UsesServiceCredentials(t *testing.T) {
	f := newAdminFlowFixture(t)
	f.h.cfg.GoogleClientID = "global-id"
	f.h.cfg.GoogleClientSecret = "global-secret"
	own := *f.svc
	ownID, ownSecret := "svc-id", "svc-secret"
	own.GoogleClientID, own.GoogleClientSecret = &ownID, &ownSecret
	plain := *f.svc
	plain.ID, plain.Domain, plain.IsDefault = "utenegen", "utenegen.test", 0

	var gotID, gotCfgID, gotSecret string
	f.h.fetchClaims = func(_ context.Context, cfg *oauth2.Config, clientID, _ string) (googleClaims, string, string) {
		gotID, gotCfgID, gotSecret = clientID, cfg.ClientID, cfg.ClientSecret
		return googleClaims{}, "", "id_token"
	}
	f.h.reg = service.NewRegistryForTest([]gen.Service{own, plain})
	run := func(svcID string) {
		st := SignState(f.cfg.OIDCStateSecret, svcID, "n")
		f.h.HandleCallback(httptest.NewRecorder(), fcCallbackReq("/callback", "oidc_state", st, "klarsyn.net"))
	}
	run("klarsyn")
	require.Equal(t, "svc-id", gotID)
	require.Equal(t, "svc-id", gotCfgID)
	require.Equal(t, "svc-secret", gotSecret)

	run("utenegen")
	require.Equal(t, "global-id", gotID, "uten egne credentials brukes de globale")
	require.Equal(t, "global-id", gotCfgID)
	require.Equal(t, "global-secret", gotSecret)
}

// S31 (Microsoft): sømmen får tjenestens egne credentials, ellers de globale.
func TestMSCallback_UsesServiceCredentials(t *testing.T) {
	f, svc := newMSFixture(t, 0, nil)
	f.h.cfg.MicrosoftClientID = "global-id"
	f.h.cfg.MicrosoftClientSecret = "global-secret"
	own := *svc
	ownID, ownSecret := "svc-id", "svc-secret"
	own.MicrosoftClientID, own.MicrosoftClientSecret = &ownID, &ownSecret
	plain := *svc
	plain.ID, plain.Domain, plain.IsDefault = "utenegen", "utenegen.test", 0
	f.h.reg = service.NewRegistryForTest([]gen.Service{own, plain})

	var gotID, gotSecret string
	f.h.fetchClaims = func(_ context.Context, cfg *oauth2.Config, _ string) (msClaims, error) {
		gotID, gotSecret = cfg.ClientID, cfg.ClientSecret
		return msClaims{}, errors.New("stopp")
	}
	run := func(svcID string) {
		st := SignState(f.h.cfg.OIDCStateSecret, svcID, "n")
		f.h.HandleCallback(httptest.NewRecorder(), fcCallbackReq("/ms-callback", "ms_state", st, ""))
	}
	run("klarsyn")
	require.Equal(t, "svc-id", gotID)
	require.Equal(t, "svc-secret", gotSecret)
	run("utenegen")
	require.Equal(t, "global-id", gotID, "uten egne credentials brukes de globale")
	require.Equal(t, "global-secret", gotSecret)
}
