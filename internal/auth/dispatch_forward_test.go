package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

const (
	fwdVin = "https://kjeller.lilleklo.work/auth/callback"
	fwdKla = "https://klarsyn.net/auth/callback"
)

// signFwd lager et access-token med vilkårlig sub, e-post, iat og org. Null-tid
// gir token uten iat.
func signFwd(iss *token.Issuer, sub, email string, iat time.Time, orgs ...string) string {
	var iatClaim *jwt.NumericDate
	if !iat.IsZero() {
		iatClaim = jwt.NewNumericDate(iat)
	}
	return iss.SignForTest(token.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "https://test.example.com", Subject: sub, ID: "jti-fwd",
			Audience:  jwt.ClaimStrings{"vinkjeller"},
			IssuedAt:  iatClaim,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
		Email: email, Org: orgs, TokenUse: "access",
	})
}

// fwdLevel er ett inngangsnivå (1-5) med målet vinkjeller. Nivå 5 har
// vinkjeller som default-tjeneste.
type fwdLevel struct {
	name, query, host, cookie string
	orgs                      []string
	defaultSvc                string
}

func fwdLevels() []fwdLevel {
	return []fwdLevel{
		{"nivå 1", "", "", fwdVin, nil, ""},
		{"nivå 2", "&service=vinkjeller", "", "", nil, ""},
		{"nivå 3", "", "auth.vin.example", "", nil, ""},
		{"nivå 4", "", "", "", []string{"vinkjeller"}, ""},
		{"nivå 5", "", "", "", nil, "vinkjeller"},
	}
}

func (l fwdLevel) fixture(t *testing.T) *audFixture {
	f := newAudFixture(t, audServices())
	if l.defaultSvc != "" {
		f.h.DefaultSvcID = l.defaultSvc
	}
	return f
}

func (l fwdLevel) dispatch(f *audFixture, tok string) *httptest.ResponseRecorder {
	return f.dispatchLevels(tok, l.query, l.host, l.cookie)
}

func requireRejectedNoToken(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, http.StatusSeeOther, w.Code)
	loc := w.Header().Get("Location")
	require.Equal(t, "/login", loc)
	require.NotContains(t, loc, "token=")
	require.NotContains(t, loc, "rt")
}

func requireForwarded(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, http.StatusSeeOther, w.Code)
	require.True(t, strings.HasPrefix(w.Header().Get("Location"), fwdVin+"?token="), w.Header().Get("Location"))
}

// K1, K5: et token fra før e-postepoken sendes ikke videre på noe nivå.
func TestDispatchLevels1to5_OldTokenRejected(t *testing.T) {
	for _, l := range fwdLevels() {
		t.Run(l.name, func(t *testing.T) {
			f := l.fixture(t)
			tok := signFwd(f.iss, "sjafor@example.com", "sjafor@example.com", time.Now().Add(-100*time.Second), l.orgs...)
			reassign(t, f, time.Now().Add(-50*time.Second))
			requireRejectedNoToken(t, l.dispatch(f, tok))
			require.Equal(t, []string{"level=1-5 reason=email_reassigned"}, f.eventsOf(t, "dispatch_subject_mismatch"))
		})
	}
}

// K1, K4: X sitt gamle token avvises etter at adressen er gitt til Y, mens Y sitt ferske rutes.
func TestDispatchLevels1to5_ReassignedAddress(t *testing.T) {
	f := newAudFixture(t, audServices())
	reassign(t, f, time.Now().Add(-50*time.Second))
	old := signFwd(f.iss, "sjafor@example.com", "sjafor@example.com", time.Now().Add(-100*time.Second))
	requireRejectedNoToken(t, f.dispatchLevels(old, "&service=vinkjeller", "", ""))
	fresh := signFwd(f.iss, "sjafor@example.com", "sjafor@example.com", time.Now())
	requireForwarded(t, f.dispatchLevels(fresh, "&service=vinkjeller", "", ""))
	require.Equal(t, []string{"level=1-5 reason=email_reassigned"}, f.eventsOf(t, "dispatch_subject_mismatch"))
}

// K2: ingen bruker, deaktivert bruker og tom e-post gir no_active_user.
func TestDispatchLevels1to5_NoActiveUser(t *testing.T) {
	t.Run("ukjent bruker", func(t *testing.T) {
		f := newAudFixture(t, audServices())
		tok := signFwd(f.iss, "ukjent@example.com", "ukjent@example.com", time.Now())
		requireRejectedNoToken(t, f.dispatchLevels(tok, "&service=vinkjeller", "", ""))
		require.Equal(t, []string{"level=1-5 reason=no_active_user"}, f.eventsOf(t, "dispatch_subject_mismatch"))
	})
	t.Run("deaktivert bruker", func(t *testing.T) {
		f := newAudFixture(t, audServices())
		_, err := f.sqld.Exec(`UPDATE users SET deactivated_at = '2026-01-01T00:00:00Z' WHERE email = 'sjafor@example.com'`)
		require.NoError(t, err)
		tok := signFwd(f.iss, "sjafor@example.com", "sjafor@example.com", time.Now())
		requireRejectedNoToken(t, f.dispatchLevels(tok, "&service=vinkjeller", "", ""))
		require.Equal(t, []string{"level=1-5 reason=no_active_user"}, f.eventsOf(t, "dispatch_subject_mismatch"))
	})
	t.Run("tom e-post", func(t *testing.T) {
		f := newAudFixture(t, audServices())
		tok := signFwd(f.iss, "sjafor@example.com", "", time.Now())
		requireRejectedNoToken(t, f.dispatchLevels(tok, "&service=vinkjeller", "", ""))
		require.Equal(t, []string{"level=1-5 reason=no_active_user"}, f.eventsOf(t, "dispatch_subject_mismatch"))
	})
}

// K3: sub som verken er e-post eller public_id avvises, på alle nivåer.
func TestDispatchLevels1to5_SubMismatch(t *testing.T) {
	for _, l := range fwdLevels() {
		t.Run(l.name, func(t *testing.T) {
			f := l.fixture(t)
			tok := signFwd(f.iss, "annen@example.com", "sjafor@example.com", time.Now(), l.orgs...)
			requireRejectedNoToken(t, l.dispatch(f, tok))
			require.Equal(t, []string{"level=1-5 reason=sub_mismatch"}, f.eventsOf(t, "dispatch_subject_mismatch"))
		})
	}
}

// K4: sub_format=id (sub = public_id) og iat i samme sekund som epoken rutes.
func TestDispatchLevels1to5_SubIDAndSameSecondForwarded(t *testing.T) {
	for _, l := range fwdLevels() {
		t.Run(l.name, func(t *testing.T) {
			f := l.fixture(t)
			u, err := f.q.GetUserByEmail(context.Background(), "sjafor@example.com")
			require.NoError(t, err)
			tok := signFwd(f.iss, u.PublicID, "sjafor@example.com", time.Now(), l.orgs...)
			requireForwarded(t, l.dispatch(f, tok))
			require.Empty(t, f.eventsOf(t, "dispatch_subject_mismatch"))
		})
	}
	t.Run("samme sekund", func(t *testing.T) {
		f := newAudFixture(t, audServices())
		sec := time.Now().UTC().Truncate(time.Second)
		reassign(t, f, sec)
		tok := signFwd(f.iss, "sjafor@example.com", "sjafor@example.com", sec)
		requireForwarded(t, f.dispatchLevels(tok, "&service=vinkjeller", "", ""))
		require.Empty(t, f.eventsOf(t, "dispatch_subject_mismatch"))
	})
}

// K1: a -> b -> a. Tokenet fra før første endring har riktig e-post og sub
// igjen, men er utstedt før siste epoke.
func TestDispatchLevels1to5_EmailRoundTrip(t *testing.T) {
	ctx := context.Background()
	f := newAudFixture(t, audServices())
	x, err := f.q.GetUserByEmail(ctx, "sjafor@example.com")
	require.NoError(t, err)
	tok := signFwd(f.iss, "sjafor@example.com", "sjafor@example.com", time.Now().Add(-100*time.Second))
	c1 := time.Now().Add(-80 * time.Second).UTC().Format(rfc3339Z)
	c2 := time.Now().Add(-50 * time.Second).UTC().Format(rfc3339Z)
	n, err := f.q.UpdateUserEmail(ctx, gen.UpdateUserEmailParams{NewEmail: "midt@example.com", EmailChangedAt: &c1, ID: x.ID, OldEmail: "sjafor@example.com"})
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	n, err = f.q.UpdateUserEmail(ctx, gen.UpdateUserEmailParams{NewEmail: "sjafor@example.com", EmailChangedAt: &c2, ID: x.ID, OldEmail: "midt@example.com"})
	require.NoError(t, err)
	require.EqualValues(t, 1, n)

	requireRejectedNoToken(t, f.dispatchLevels(tok, "&service=vinkjeller", "", ""))
	require.Equal(t, []string{"level=1-5 reason=email_reassigned"}, f.eventsOf(t, "dispatch_subject_mismatch"))
}

// K6: DB-feil i oppslaget er fail-open. Tokenet er signaturverifisert, og en
// DB-feil skal ikke gi 5xx eller låse ute alle.
func TestDispatchLevels1to5_DBErrorFailsOpen(t *testing.T) {
	f := newAudFixture(t, audServices())
	tok := signFwd(f.iss, "sjafor@example.com", "sjafor@example.com", time.Now())
	require.NoError(t, f.sqld.Close())
	w := f.dispatchLevels(tok, "&service=vinkjeller", "", "")
	require.Less(t, w.Code, 500)
	requireForwarded(t, w)
}

// K6: fail-open auditeres. Oppslaget feiles med en manglende users-tabell,
// slik at audit-tabellen fortsatt kan skrives.
func TestDispatchLevels1to5_DBErrorAudited(t *testing.T) {
	f := newAudFixture(t, audServices())
	tok := signFwd(f.iss, "sjafor@example.com", "sjafor@example.com", time.Now())
	_, err := f.sqld.Exec(`PRAGMA foreign_keys = OFF; DROP TABLE users`)
	require.NoError(t, err)
	requireForwarded(t, f.dispatchLevels(tok, "&service=vinkjeller", "", ""))
	// Uten iat når tokenet bare ferskhets-auditen via fail-open.
	noIat := signFwd(f.iss, "sjafor@example.com", "sjafor@example.com", time.Time{})
	requireForwarded(t, f.dispatchLevels(noIat, "&service=vinkjeller", "", ""))
	require.Equal(t, []string{"level=1-5 reason=db_error", "level=1-5 reason=db_error"}, f.eventsOf(t, "dispatch_subject_check_skipped"))
	require.Equal(t, []string{"level=1-5 iat=missing mode=audit"}, f.eventsOf(t, "dispatch_token_stale"))
	require.Empty(t, f.eventsOf(t, "dispatch_subject_mismatch"))
}

// K6: en klient som har koblet fra, gir ingen fail-open-audit.
func TestDispatchLevels1to5_CanceledClientNotAudited(t *testing.T) {
	f := newAudFixture(t, audServices())
	tok := signFwd(f.iss, "sjafor@example.com", "sjafor@example.com", time.Now())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/dispatch?token="+tok+"&service=vinkjeller", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	f.h.ServeDispatch(w, req)
	require.Less(t, w.Code, 500)
	require.Empty(t, f.eventsOf(t, "dispatch_subject_check_skipped"))
}

// K4: e-postclaimen normaliseres før oppslaget, som ved innlogging.
func TestDispatchLevels1to5_EmailClaimNormalized(t *testing.T) {
	f := newAudFixture(t, audServices())
	tok := signFwd(f.iss, "sjafor@example.com", "  Sjafor@Example.COM ", time.Now())
	requireForwarded(t, f.dispatchLevels(tok, "&service=vinkjeller", "", ""))
	require.Empty(t, f.eventsOf(t, "dispatch_subject_mismatch"))
}

// K7: gammelt token videresendes, men auditeres som dispatch_token_stale
// mode=audit med success=1. Ferskt token gir ingen rad.
func TestDispatchLevels1to5_StaleTokenAuditedNotBlocked(t *testing.T) {
	staleEvents := func(t *testing.T, f *audFixture) []gen.AuditEvent {
		t.Helper()
		require.NoError(t, f.h.Audit.Close(context.Background()))
		all, err := f.q.ListAuditEvents(context.Background(), gen.ListAuditEventsParams{Limit: 100})
		require.NoError(t, err)
		var out []gen.AuditEvent
		for _, e := range all {
			if e.EventType == "dispatch_token_stale" {
				out = append(out, e)
			}
		}
		return out
	}
	for _, l := range fwdLevels() {
		t.Run(l.name+" gammelt", func(t *testing.T) {
			f := l.fixture(t)
			tok := signFwd(f.iss, "sjafor@example.com", "sjafor@example.com", time.Now().Add(-10*time.Minute), l.orgs...)
			requireForwarded(t, l.dispatch(f, tok))
			ev := staleEvents(t, f)
			require.Len(t, ev, 1)
			require.EqualValues(t, 1, ev[0].Success)
			require.NotNil(t, ev[0].Details)
			require.Regexp(t, `^level=1-5 age_s=\d+ mode=audit$`, *ev[0].Details)
		})
	}
	// Uten iat kan epoken ikke bevises: avvist med egen grunn, ingen ferskhets-rad.
	t.Run("uten iat", func(t *testing.T) {
		f := newAudFixture(t, audServices())
		tok := signFwd(f.iss, "sjafor@example.com", "sjafor@example.com", time.Time{})
		requireRejectedNoToken(t, f.dispatchLevels(tok, "&service=vinkjeller", "", ""))
		require.Empty(t, staleEvents(t, f))
		require.Equal(t, []string{"level=1-5 reason=iat_missing"}, f.eventsOf(t, "dispatch_subject_mismatch"))
	})
	t.Run("ferskt", func(t *testing.T) {
		f := newAudFixture(t, audServices())
		tok := signFwd(f.iss, "sjafor@example.com", "sjafor@example.com", time.Now())
		requireForwarded(t, f.dispatchLevels(tok, "&service=vinkjeller", "", ""))
		require.Empty(t, staleEvents(t, f))
	})
}

// K5: verken token, rt eller sub havner i audit-details.
func TestDispatchLevels1to5_AuditDetailsLeakNothing(t *testing.T) {
	f := newAudFixture(t, audServices())
	const sub = "hemmelig-sub@example.com"
	// stale må gå før reassign, ellers avvises den som email_reassigned og
	// ferskhets-auditen blir aldri skrevet.
	stale := signFwd(f.iss, "sjafor@example.com", "sjafor@example.com", time.Now().Add(-10*time.Minute))
	f.dispatchLevels(stale, "&service=vinkjeller&rt=hemmelig-rt", "", "")
	reassign(t, f, time.Now().Add(-50*time.Second))
	old := signFwd(f.iss, "sjafor@example.com", "sjafor@example.com", time.Now().Add(-100*time.Second))
	bad := signFwd(f.iss, sub, "sjafor@example.com", time.Now())
	for _, tok := range []string{old, bad} {
		f.dispatchLevels(tok, "&service=vinkjeller&rt=hemmelig-rt", "", "")
	}
	require.NoError(t, f.h.Audit.Close(context.Background()))
	all, err := f.q.ListAuditEvents(context.Background(), gen.ListAuditEventsParams{Limit: 100})
	require.NoError(t, err)
	types := map[string]int{}
	for _, e := range all {
		types[e.EventType]++
		if e.Details == nil {
			continue
		}
		for _, secret := range []string{old, bad, stale, "hemmelig-rt", sub} {
			require.NotContains(t, *e.Details, secret)
		}
	}
	// Alle tre veiene har faktisk skrevet en rad, ellers tester løkken ingenting.
	require.Equal(t, 1, types["dispatch_token_stale"])
	require.Equal(t, 2, types["dispatch_subject_mismatch"])
}
