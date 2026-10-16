package auth

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
)

// D4: Details er "reason=<årsak>", med kontekst foran når den er satt. MS
// bruker konteksten (tid=…) fra F6; formatet låses her.
func TestRejection_Details(t *testing.T) {
	require.Equal(t, "reason=nonce", rejection{Reason: "nonce"}.details())
	require.Equal(t, "reason=user_conflict", rejection{Email: "a@b.no", Reason: "user_conflict"}.details())
	require.Equal(t, "tid=abc reason=edov", rejection{Context: "tid=abc", Reason: "edov"}.details())
}

// googleCountingFetch teller kall til sømmen, så testene kan vise at ugyldig
// state avvises før noe nettverk er berørt.
func googleCountingFetch(calls *atomic.Int32, cl googleClaims, tokenNonce string) func(context.Context, *oauth2.Config, string, string) (googleClaims, string, string) {
	return func(context.Context, *oauth2.Config, string, string) (googleClaims, string, string) {
		calls.Add(1)
		return cl, tokenNonce, ""
	}
}

func googleCallbackWith(path, cookieState, paramState string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path+"?code=c&state="+url.QueryEscape(paramState), nil)
	req.Host = "klarsyn.net"
	req.AddCookie(&http.Cookie{Name: "oidc_state", Value: cookieState})
	return req
}

func requireNoGoogleRejection(t *testing.T, f *adminFlowFixture) {
	t.Helper()
	require.Empty(t, lbOfType(drainAudit(t, f.q, f.h.aud), "google_oidc_rejected"))
}

// Google-variant av MS-testen: cookie og param er hver for seg gyldig signert,
// men ulike.
func TestGoogleCallback_CookieAndParamDiffer_Rejected(t *testing.T) {
	f := newAdminFlowFixture(t)
	var calls atomic.Int32
	f.h.fetchClaims = googleCountingFetch(&calls, googleClaims{Sub: "s", Iss: googleIssuer, Email: "vanlig@example.com", EmailVerified: true}, "n1")
	cookieState := SignState(f.cfg.OIDCStateSecret, "klarsyn", "n1")
	paramState := SignState(f.cfg.OIDCStateSecret, "klarsyn", "n2")
	require.NotEqual(t, cookieState, paramState)
	w := httptest.NewRecorder()
	f.h.HandleCallback(w, googleCallbackWith("/callback", cookieState, paramState))

	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Equal(t, "/login?error=login_failed", w.Header().Get("Location"))
	require.Equal(t, int32(0), calls.Load())
	require.Empty(t, w.Result().Cookies())
	requireNoGoogleRejection(t, f)
}

// D10 gjennom readState: state som ikke består parseState (forfalsket
// signatur, utløpt) gir login_failed uten tjeneste, uten kall til sømmen og
// uten audit-rad, også når cookie og param er like.
func TestGoogleCallback_InvalidState_NoServiceNoAudit(t *testing.T) {
	f := newAdminFlowFixture(t)
	secret := f.cfg.OIDCStateSecret
	valid := SignState(secret, "klarsyn", "n1")
	raw, err := base64.RawURLEncoding.DecodeString(valid)
	require.NoError(t, err)
	dot := strings.LastIndex(string(raw), ".")
	forged := base64.RawURLEncoding.EncodeToString([]byte(string(raw[:dot]) + "." + strings.Repeat("0", 64)))
	otherKey := SignState([]byte("annen-hemmelighet-32bytes-padded"), "klarsyn", "n1")
	expired := signStatePayload(secret, "klarsyn:n1:1")

	for name, st := range map[string]string{"forfalsket signatur": forged, "annen nøkkel": otherKey, "utløpt": expired} {
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			f.h.fetchClaims = googleCountingFetch(&calls, googleClaims{Sub: "s", Iss: googleIssuer, Email: "vanlig@example.com", EmailVerified: true}, "n1")
			w := httptest.NewRecorder()
			f.h.HandleCallback(w, googleCallbackWith("/callback", st, st))

			require.Equal(t, http.StatusSeeOther, w.Code)
			require.Equal(t, "/login?error=login_failed", w.Header().Get("Location"))
			require.Equal(t, int32(0), calls.Load())
			require.Empty(t, w.Result().Cookies())
		})
	}
	requireNoGoogleRejection(t, f)
}

// T1: ingen konto (tjeneste uten auto-registrering) gir access_denied uten
// avvisningsrad, så en utenforstående ikke kan se hvilke adresser som finnes.
func TestGoogleCallback_NoAccount_AccessDeniedNotAudited(t *testing.T) {
	f := newAdminFlowFixture(t)
	noReg := *f.svc
	noReg.AutoRegister = 0
	f.h.reg = service.NewRegistryForTest([]gen.Service{noReg})
	var calls atomic.Int32
	f.h.fetchClaims = googleCountingFetch(&calls, googleClaims{Sub: "s", Iss: googleIssuer, Email: "ukjent@example.com", EmailVerified: true}, "n1")
	st := SignState(f.cfg.OIDCStateSecret, "klarsyn", "n1")
	w := httptest.NewRecorder()
	f.h.HandleCallback(w, googleCallbackWith("/callback", st, st))

	require.Equal(t, int32(1), calls.Load())
	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Equal(t, "/login?error=access_denied&service=klarsyn", w.Header().Get("Location"))
	requireNoGoogleRejection(t, f)
}

// T2 + T3: feil nonce og uverifisert e-post samtidig gir reason=nonce
// (nonce sjekkes først), og raden har auth_method google.
func TestGoogleCallback_NonceBeforeEmailVerified_AuthMethodSet(t *testing.T) {
	f := newAdminFlowFixture(t)
	f.h.fetchClaims = googleCountingFetch(new(atomic.Int32), googleClaims{Sub: "s", Iss: googleIssuer, Email: "vanlig@example.com", EmailVerified: false}, "feil-nonce")
	st := SignState(f.cfg.OIDCStateSecret, "klarsyn", "n1")
	w := httptest.NewRecorder()
	f.h.HandleCallback(w, googleCallbackWith("/callback", st, st))

	require.Equal(t, "/login?error=login_failed&service=klarsyn", w.Header().Get("Location"))
	ev := lbOfType(drainAudit(t, f.q, f.h.aud), "google_oidc_rejected")
	require.Len(t, ev, 1)
	require.Equal(t, "reason=nonce", fcDetails(t, ev[0]))
	require.NotNil(t, ev[0].AuthMethod)
	require.Equal(t, "google", *ev[0].AuthMethod)
}

// tid kommer fra IdP-en og renses før den havner i audit-details: kontrolltegn
// fjernes (ingen linjeskift-injeksjon), mellomrom beholdes.
func TestMSFinish_TidIsSanitizedInDetails(t *testing.T) {
	f, svc := newMSFixture(t, 0, nil)
	cl := msValid(msOrgTid, msBool(true))
	cl.Tid = "evil tid\r\nINJECT\x00"
	cl.Iss = "ikke-matchende"
	w := httptest.NewRecorder()
	f.h.finishCallback(w, httptest.NewRequest(http.MethodGet, "/ms-callback", nil), svc, cl, msTestNon)

	require.Equal(t, http.StatusSeeOther, w.Code)
	ev := lbOfType(drainAudit(t, f.q, f.h.aud), "microsoft_oidc_rejected")
	require.Len(t, ev, 1)
	require.Equal(t, "tid=evil tidINJECT reason=issuer", fcDetails(t, ev[0]))
	require.Empty(t, ev[0].Email)
}

// D10 for Microsoft: readState er felles, så ugyldig eller utløpt state skal gi
// samme svar som hos Google, uten tjeneste, uten kodeutveksling og uten audit.
func TestMSCallback_InvalidState_NoServiceNoAudit(t *testing.T) {
	f, _ := newMSFixture(t, 0, nil)
	secret := f.h.cfg.OIDCStateSecret
	valid := SignState(secret, "klarsyn", "n1")
	raw, err := base64.RawURLEncoding.DecodeString(valid)
	require.NoError(t, err)
	dot := strings.LastIndex(string(raw), ".")
	forged := base64.RawURLEncoding.EncodeToString([]byte(string(raw[:dot]) + "." + strings.Repeat("0", 64)))
	otherKey := SignState([]byte("annen-hemmelighet-32bytes-padded"), "klarsyn", "n1")
	expired := signStatePayload(secret, "klarsyn:n1:1")

	var calls atomic.Int32
	f.h.fetchClaims = func(context.Context, *oauth2.Config, string) (msClaims, error) {
		calls.Add(1)
		return msClaims{}, nil
	}
	for name, st := range map[string]string{"forfalsket signatur": forged, "annen nøkkel": otherKey, "utløpt": expired} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/ms-callback?code=c&state="+url.QueryEscape(st), nil)
			req.AddCookie(&http.Cookie{Name: "ms_state", Value: st})
			w := httptest.NewRecorder()
			f.h.HandleCallback(w, req)

			require.Equal(t, http.StatusSeeOther, w.Code)
			require.Equal(t, "/login?error=login_failed", w.Header().Get("Location"))
			require.Empty(t, w.Result().Cookies())
		})
	}
	require.Equal(t, int32(0), calls.Load())
	require.Empty(t, lbOfType(drainAudit(t, f.q, f.h.aud), "microsoft_oidc_rejected"))
}

// missing_oid er en avvisning på claim-nivå: tid-konteksten står foran årsaken
// og e-posten er tom, som for de andre claim-årsakene (AK6.2).
func TestMSFinish_MissingOID_HasTidContext(t *testing.T) {
	f, svc := newMSFixture(t, 1, nil)
	cl := msValid(msOrgTid, msBool(true))
	cl.Oid = ""
	msFinish(f, svc, cl)
	ev := msAuditEvents(t, f, "microsoft_oidc_rejected", 1)
	require.Equal(t, "tid="+msOrgTid+" reason=missing_oid", *ev[0].Details)
	require.True(t, ev[0].Email == nil || *ev[0].Email == "")
}
