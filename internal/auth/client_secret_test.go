package auth

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
)

func sp(s string) *string { return &s }

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// captureLog fanger slog-utskrift i testen.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

func TestResolveClientSecret_Matrix(t *testing.T) {
	env := envMap(map[string]string{"KAUTH_SVC_A_GOOGLE_SECRET": "fra-env", "KAUTH_SVC_TOM": ""})
	svc := &gen.Service{ID: "a"}
	for _, tc := range []struct {
		name        string
		ref, col    *string
		global      string
		want        string
		wantMissing bool
	}{
		{"ref satt og env satt vinner over kolonne og global", sp("KAUTH_SVC_A_GOOGLE_SECRET"), sp("kolonne"), "global", "fra-env", false},
		{"ref satt men env tom: feil, ingen fallback til kolonne", sp("KAUTH_SVC_TOM"), sp("kolonne"), "global", "", true},
		{"ref satt men env ikke definert: feil, ingen fallback til global", sp("KAUTH_SVC_FINNES_IKKE"), nil, "global", "", true},
		{"ref ikke satt, kolonne satt", nil, sp("kolonne"), "global", "kolonne", false},
		{"ref tom streng behandles som ikke satt", sp(""), sp("kolonne"), "global", "kolonne", false},
		{"ref ikke satt, kolonne tom: global", nil, sp(""), "global", "global", false},
		{"ingenting: tom global", nil, nil, "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveClientSecret(env, svc, "google", tc.ref, tc.col, tc.global)
			require.Equal(t, tc.want, got)
			if tc.wantMissing {
				require.ErrorIs(t, err, errClientSecretMissing)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestResolveClientSecret_InvalidNameNeverReadsEnv(t *testing.T) {
	calls := 0
	getenv := func(string) string { calls++; return "hemmelig" }
	for _, name := range []string{"KAUTH_PRIVATE_KEY_PEM", "kauth_svc_a", "KAUTH_SVC_", "KAUTH_SVC_Å"} {
		_, err := resolveClientSecret(getenv, &gen.Service{ID: "x-" + name}, "google", sp(name), sp(secColumn), secGlobal)
		require.ErrorIs(t, err, errClientSecretMissing, name)
	}
	require.Zero(t, calls)
	// Bare blanke tegn teller som tom.
	_, err := resolveClientSecret(func(string) string { return "  \n" }, &gen.Service{ID: "b"}, "google", sp("KAUTH_SVC_B"), nil, "")
	require.ErrorIs(t, err, errClientSecretMissing)
}

func TestResolveClientSecret_LogRateLimited(t *testing.T) {
	buf := captureLog(t)
	svc := &gen.Service{ID: "rate-test"}
	for i := 0; i < 5; i++ {
		_, _ = resolveClientSecret(envMap(nil), svc, "google", sp("KAUTH_SVC_RATE"), nil, "")
	}
	require.Equal(t, 1, strings.Count(buf.String(), "level=WARN"))
	require.NotContains(t, buf.String(), "level=ERROR")
}

func TestGoogleClientSecret_UsesGlobalAndColumnAndEnv(t *testing.T) {
	f := newAdminFlowFixture(t)
	f.h.cfg.GoogleClientSecret = "global-g"
	f.h.getenv = envMap(map[string]string{"KAUTH_SVC_KLARSYN_GOOGLE_SECRET": "env-g"})
	svc := &gen.Service{ID: "klarsyn"}
	s, err := f.h.clientSecret(svc)
	require.NoError(t, err)
	require.Equal(t, "global-g", s)
	svc.GoogleClientSecret = sp("kol-g")
	s, _ = f.h.clientSecret(svc)
	require.Equal(t, "kol-g", s)
	svc.GoogleClientSecretEnv = sp("KAUTH_SVC_KLARSYN_GOOGLE_SECRET")
	s, _ = f.h.clientSecret(svc)
	require.Equal(t, "env-g", s)
}

func TestMicrosoftClientSecret_UsesGlobalAndColumnAndEnv(t *testing.T) {
	f, _ := newMSFixture(t, 0, nil)
	f.h.cfg.MicrosoftClientSecret = "global-m"
	f.h.getenv = envMap(map[string]string{"KAUTH_SVC_KLARSYN_MS_SECRET": "env-m"})
	svc := &gen.Service{ID: "klarsyn"}
	s, err := f.h.clientSecret(svc)
	require.NoError(t, err)
	require.Equal(t, "global-m", s)
	svc.MicrosoftClientSecret = sp("kol-m")
	s, _ = f.h.clientSecret(svc)
	require.Equal(t, "kol-m", s)
	svc.MicrosoftClientSecretEnv = sp("KAUTH_SVC_KLARSYN_MS_SECRET")
	s, _ = f.h.clientSecret(svc)
	require.Equal(t, "env-m", s)
}

const (
	secGlobal = "GLOBAL-HEMMELIGHET-XYZ"
	secColumn = "KOLONNE-HEMMELIGHET-XYZ"
)

func TestGoogle_EmptyRef_StartAndCallbackFail_NoFallback(t *testing.T) {
	f := newAdminFlowFixture(t)
	buf := captureLog(t)
	f.h.cfg.GoogleClientSecret = secGlobal
	f.h.cfg.GoogleClientID = "cid"
	f.h.getenv = envMap(nil)
	f.svcs[0].GoogleClientSecret = sp(secColumn)
	f.svcs[0].GoogleClientSecretEnv = sp("KAUTH_SVC_KLARSYN_GOOGLE_SECRET")

	// Start: avvist før brukeren sendes til Google.
	req := httptest.NewRequest(http.MethodGet, "/social-login", nil)
	req.Host = "klarsyn.net"
	w := httptest.NewRecorder()
	f.h.InitiateLogin(w, req)
	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Equal(t, "/login?error=login_failed&service=klarsyn", w.Header().Get("Location"))
	require.Nil(t, cookieNamed(w, "oidc_state"))

	// Admin-start avvises også, til admin-login.
	w = httptest.NewRecorder()
	f.h.InitiateAdminLogin(w, req)
	require.Equal(t, "/admin/login?err=ingen_tilgang", w.Header().Get("Location"))

	// Callback: kodeutvekslingen nås aldri.
	called := false
	f.h.fetchClaims = func(context.Context, *oauth2.Config, string, string) (googleClaims, string, string) {
		called = true
		return googleClaims{}, "", ""
	}
	st := SignState(f.cfg.OIDCStateSecret, "klarsyn", "n")
	req = httptest.NewRequest(http.MethodGet, "/callback?code=x&state="+url.QueryEscape(st), nil)
	req.Host = "klarsyn.net"
	req.AddCookie(&http.Cookie{Name: "oidc_state", Value: st})
	w = httptest.NewRecorder()
	f.h.HandleCallback(w, req)
	require.Equal(t, "/login?error=login_failed&service=klarsyn", w.Header().Get("Location"))
	require.False(t, called)

	out := buf.String()
	require.Contains(t, out, "klienthemmelighet mangler")
	require.Contains(t, out, "KAUTH_SVC_KLARSYN_GOOGLE_SECRET")
	require.NotContains(t, out, secGlobal)
	require.NotContains(t, out, secColumn)
}

func TestGoogle_RefSet_CallbackExchangesWithEnvSecret(t *testing.T) {
	f := newAdminFlowFixture(t)
	f.h.cfg.GoogleClientSecret = secGlobal
	f.h.getenv = envMap(map[string]string{"KAUTH_SVC_KLARSYN_GOOGLE_SECRET": "env-verdi"})
	f.svcs[0].GoogleClientSecretEnv = sp("KAUTH_SVC_KLARSYN_GOOGLE_SECRET")

	var gotSecret string
	f.h.fetchClaims = func(_ context.Context, c *oauth2.Config, _, _ string) (googleClaims, string, string) {
		gotSecret = c.ClientSecret
		return googleClaims{}, "", "stopp"
	}
	st := SignState(f.cfg.OIDCStateSecret, "klarsyn", "n")
	req := httptest.NewRequest(http.MethodGet, "/callback?code=x&state="+url.QueryEscape(st), nil)
	req.Host = "klarsyn.net"
	req.AddCookie(&http.Cookie{Name: "oidc_state", Value: st})
	f.h.HandleCallback(httptest.NewRecorder(), req)
	require.Equal(t, "env-verdi", gotSecret)

	// Start virker når referansen er løst.
	f.h.cfg.GoogleClientID = "cid"
	w := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodGet, "/social-login", nil)
	r2.Host = "klarsyn.net"
	f.h.InitiateLogin(w, r2)
	require.Equal(t, http.StatusFound, w.Code)
	require.NotNil(t, cookieNamed(w, "oidc_state"))
}

func TestMicrosoft_EmptyRef_StartAndCallbackFail_NoFallback(t *testing.T) {
	f, svc := newMSFixture(t, 0, nil)
	buf := captureLog(t)
	f.h.cfg.MicrosoftClientSecret = secGlobal
	f.h.cfg.MicrosoftClientID = "cid"
	f.h.getenv = envMap(nil)
	svc.MicrosoftClientSecret = sp(secColumn)
	svc.MicrosoftClientSecretEnv = sp("KAUTH_SVC_KLARSYN_MS_SECRET")
	f.h.reg = service.NewRegistryForTest([]gen.Service{*svc})

	w := httptest.NewRecorder()
	f.h.InitiateLogin(w, httptest.NewRequest(http.MethodGet, "https://klarsyn.net/ms-oidc-login", nil))
	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Equal(t, "/login?error=login_failed&service=klarsyn", w.Header().Get("Location"))
	require.Empty(t, w.Result().Cookies())

	called := false
	f.h.fetchClaims = func(context.Context, *oauth2.Config, string) (msClaims, error) {
		called = true
		return msClaims{}, nil
	}
	st := SignState(f.h.cfg.OIDCStateSecret, "klarsyn", "n")
	req := httptest.NewRequest(http.MethodGet, "/ms-callback?code=x&state="+url.QueryEscape(st), nil)
	req.AddCookie(&http.Cookie{Name: "ms_state", Value: st})
	w = httptest.NewRecorder()
	f.h.HandleCallback(w, req)
	require.Equal(t, "/login?error=login_failed&service=klarsyn", w.Header().Get("Location"))
	require.False(t, called)

	out := buf.String()
	require.Contains(t, out, "KAUTH_SVC_KLARSYN_MS_SECRET")
	require.NotContains(t, out, secGlobal)
	require.NotContains(t, out, secColumn)
}

func TestMicrosoft_RefSet_CallbackExchangesWithEnvSecret(t *testing.T) {
	f, svc := newMSFixture(t, 0, nil)
	f.h.cfg.MicrosoftClientSecret = secGlobal
	f.h.getenv = envMap(map[string]string{"KAUTH_SVC_KLARSYN_MS_SECRET": "env-verdi"})
	svc.MicrosoftClientSecretEnv = sp("KAUTH_SVC_KLARSYN_MS_SECRET")
	f.h.reg = service.NewRegistryForTest([]gen.Service{*svc})
	var got string
	f.h.fetchClaims = func(_ context.Context, c *oauth2.Config, _ string) (msClaims, error) {
		got = c.ClientSecret
		return msClaims{}, http.ErrAbortHandler
	}
	st := SignState(f.h.cfg.OIDCStateSecret, "klarsyn", "n")
	req := httptest.NewRequest(http.MethodGet, "/ms-callback?code=x&state="+url.QueryEscape(st), nil)
	req.AddCookie(&http.Cookie{Name: "ms_state", Value: st})
	f.h.HandleCallback(httptest.NewRecorder(), req)
	require.Equal(t, "env-verdi", got)
}

// En tom Google-referanse tar bare Google ut; magic link for samme tjeneste virker.
func TestMagicLink_UnaffectedByEmptyGoogleRef(t *testing.T) {
	p := magicSvc("klarsyn", 1, 1)
	p.AuthGoogle = 1
	p.GoogleClientSecretEnv = sp("KAUTH_SVC_KLARSYN_GOOGLE_SECRET")
	f := newMagicFixture(t, p)
	w, _ := f.request(f.h, "a@x.no", "klarsyn")
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, 1, f.mailer.count())
}
