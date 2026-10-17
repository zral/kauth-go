package auth

import (
	"encoding/base64"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var stateSecret = []byte("test-secret-32bytes-padded-here!")

var stateT0 = time.Unix(1_800_000_000, 0)

// fixClock fryser pakkeklokken og gjenoppretter den etter testen.
func fixClock(t *testing.T, at time.Time) {
	t.Helper()
	orig := now
	now = func() time.Time { return at }
	t.Cleanup(func() { now = orig })
}

// rawState signerer en vilkårlig payload, for å lage formater SignState ikke lager.
func rawState(payload string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(payload + "." + computeHMAC(stateSecret, payload)))
}

func iatStr(d time.Duration) string {
	return strconv.FormatInt(stateT0.Add(d).Unix(), 10)
}

func TestParseState_AdminRoundtrip(t *testing.T) {
	fixClock(t, stateT0)
	c, ok := parseState(stateSecret, signAdminState(stateSecret, "klarsyn", "abc123"))
	require.True(t, ok)
	require.True(t, c.Admin)
	require.Equal(t, "klarsyn", c.ServiceID)
}

func TestParseState_LoginRoundtripIsNotAdmin(t *testing.T) {
	fixClock(t, stateT0)
	c, ok := parseState(stateSecret, SignState(stateSecret, "klarsyn", "abc123"))
	require.True(t, ok)
	require.False(t, c.Admin)
	require.Equal(t, "klarsyn", c.ServiceID)
}

func TestParseState_NonceRoundTrip(t *testing.T) {
	fixClock(t, stateT0)
	c, ok := parseState(stateSecret, SignState(stateSecret, "klarsyn", "deadbeef01"))
	require.True(t, ok)
	require.Equal(t, "deadbeef01", c.Nonce)

	c, ok = parseState(stateSecret, signAdminState(stateSecret, "a:b", "cafe02"))
	require.True(t, ok)
	require.True(t, c.Admin)
	require.Equal(t, "cafe02", c.Nonce)
	require.Equal(t, "a:b", c.ServiceID)
}

func TestParseState_Expiry(t *testing.T) {
	tests := []struct {
		name string
		age  time.Duration // now - iat; negativ = iat i fremtiden
		ok   bool
	}{
		{"fersk", 0, true},
		{"9:59", 9*time.Minute + 59*time.Second, true},
		{"10:00", 10 * time.Minute, true},
		{"10:01", 10*time.Minute + time.Second, false},
		{"+59s", -59 * time.Second, true},
		{"+60s", -60 * time.Second, true},
		{"+61s", -61 * time.Second, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixClock(t, stateT0)
			st := rawState("klarsyn:n1:" + iatStr(-tt.age))
			_, ok := parseState(stateSecret, st)
			require.Equal(t, tt.ok, ok)
			adm := rawState("klarsyn:n1:" + iatStr(-tt.age) + ":admin")
			_, ok = parseState(stateSecret, adm)
			require.Equal(t, tt.ok, ok)
		})
	}

	t.Run("uten iat", func(t *testing.T) {
		fixClock(t, stateT0)
		_, ok := parseState(stateSecret, rawState("klarsyn:n1:"))
		require.False(t, ok)
	})
	t.Run("iat ikke tall", func(t *testing.T) {
		fixClock(t, stateT0)
		_, ok := parseState(stateSecret, rawState("klarsyn:n1:nu"))
		require.False(t, ok)
	})
	t.Run("signert med klokken, lest senere", func(t *testing.T) {
		fixClock(t, stateT0)
		st := SignState(stateSecret, "klarsyn", "n1")
		fixClock(t, stateT0.Add(10*time.Minute+time.Second))
		_, ok := parseState(stateSecret, st)
		require.False(t, ok)
	})
}

func TestParseState_LegacyFormatRejected(t *testing.T) {
	fixClock(t, stateT0)
	for _, p := range []string{"klarsyn:legacynonce", "klarsyn:legacynonce:admin"} {
		_, ok := parseState(stateSecret, rawState(p))
		require.False(t, ok, p)
	}
}

func TestParseState_UnknownPurposeRejected(t *testing.T) {
	fixClock(t, stateT0)
	_, ok := parseState(stateSecret, rawState("klarsyn:nonce:"+iatStr(0)+":superuser"))
	require.False(t, ok)
}

// Manipulert iat (eller formål) uten ny signatur gir ugyldig HMAC.
func TestParseState_TamperedFailsHMAC(t *testing.T) {
	fixClock(t, stateT0)
	payload := "klarsyn:nonce:" + iatStr(-20*time.Minute)
	mac := computeHMAC(stateSecret, payload)

	// Ny iat med gammel signatur.
	forgedIat := base64.RawURLEncoding.EncodeToString([]byte("klarsyn:nonce:" + iatStr(0) + "." + mac))
	_, ok := parseState(stateSecret, forgedIat)
	require.False(t, ok)

	// ":admin" hektet på uten ny signatur.
	forged := base64.RawURLEncoding.EncodeToString([]byte(payload + ":admin." + mac))
	_, ok = parseState(stateSecret, forged)
	require.False(t, ok)

	// Admin-state der purpose strippes.
	adminPayload := "klarsyn:nonce:" + iatStr(0) + ":admin"
	stripped := base64.RawURLEncoding.EncodeToString([]byte("klarsyn:nonce:" + iatStr(0) + "." + computeHMAC(stateSecret, adminPayload)))
	_, ok = parseState(stateSecret, stripped)
	require.False(t, ok)
}

func TestParseState_WrongSecretFails(t *testing.T) {
	fixClock(t, stateT0)
	st := signAdminState(stateSecret, "klarsyn", "n")
	_, ok := parseState([]byte("annen-secret-32bytes-padded-!!!!"), st)
	require.False(t, ok)
}

// En admin-state skal ikke kunne gjenbrukes av flyter som bare kjenner
// VerifyState (Microsoft-callbacken): den gir ikke en vanlig innlogging.
func TestVerifyState_RejectsAdminState(t *testing.T) {
	fixClock(t, stateT0)
	_, ok := VerifyState(stateSecret, signAdminState(stateSecret, "klarsyn", "n"))
	require.False(t, ok)
}

// Tjeneste-ID med ":" skal rundturs riktig, og aldri forveksles med et formål.
func TestParseState_ServiceIDWithColon(t *testing.T) {
	fixClock(t, stateT0)
	c, ok := parseState(stateSecret, signAdminState(stateSecret, "a:b", "n1"))
	require.True(t, ok)
	require.True(t, c.Admin)
	require.Equal(t, "a:b", c.ServiceID)

	c, ok = parseState(stateSecret, SignState(stateSecret, "a:b", "n1"))
	require.True(t, ok)
	require.False(t, c.Admin)
	require.Equal(t, "a:b", c.ServiceID)

	// Tjeneste-ID "x:admin" i en vanlig state er ikke admin.
	c, ok = parseState(stateSecret, SignState(stateSecret, "x:admin", "n1"))
	require.True(t, ok)
	require.False(t, c.Admin)
	require.Equal(t, "x:admin", c.ServiceID)
}

// Færre enn fire segmenter kan aldri være admin.
func TestParseState_ThreeSegmentsEndingAdminIsNotAdmin(t *testing.T) {
	fixClock(t, stateT0)
	_, ok := parseState(stateSecret, rawState("klarsyn:"+iatStr(0)+":admin"))
	require.False(t, ok)
}

func TestParseState_GitHub(t *testing.T) {
	fixClock(t, stateT0)
	iat := iatStr(0)
	tests := []struct {
		name    string
		payload string
		ok      bool
		svc     string
		nonce   string
	}{
		{"github alene", "klarsyn:n1:" + iat + ":github", true, "klarsyn", "n1"},
		{"tjeneste-ID med kolon", "a:b:n1:" + iat + ":github", true, "a:b", "n1"},
		{"github + admin (admin bak)", "klarsyn:n1:" + iat + ":github:admin", false, "", ""},
		{"github + admin (admin foran)", "klarsyn:n1:" + iat + ":admin:github", false, "", ""},
		{"github + idp", "klarsyn:n1:" + iat + ":idp=acme:github", false, "", ""},
		{"idp + github", "klarsyn:n1:" + iat + ":github:idp=acme", false, "", ""},
		{"github + link", "klarsyn:n1:" + iat + ":idp=acme:link=7:github", false, "", ""},
		{"link + github", "klarsyn:n1:" + iat + ":idp=acme:github:link=7", false, "", ""},
		{"to github-suffikser", "klarsyn:n1:" + iat + ":github:github", false, "", ""},
		{"kort payload (tre segmenter)", "n1:" + iat + ":github", false, "", ""},
		{"bare github", "github", false, "", ""},
		{"stor bokstav", "klarsyn:n1:" + iat + ":GitHub", false, "", ""},
		{"github uten iat", "klarsyn:n1:github", false, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, ok := parseState(stateSecret, rawState(tc.payload))
			require.Equal(t, tc.ok, ok)
			if !ok {
				return
			}
			require.Equal(t, stateClaims{ServiceID: tc.svc, Nonce: tc.nonce, GitHub: true}, c)
		})
	}
}

func TestSignGitHubState_RoundtripAndRejectedByVerifyState(t *testing.T) {
	fixClock(t, stateT0)
	s := signGitHubState(stateSecret, "a:b", "n9")
	c, ok := parseState(stateSecret, s)
	require.True(t, ok)
	require.Equal(t, stateClaims{ServiceID: "a:b", Nonce: "n9", GitHub: true}, c)

	_, ok = VerifyState(stateSecret, s)
	require.False(t, ok, "VerifyState skal avvise GitHub-state")

	_, ok = parseState([]byte("annen-hemmelighet-32-bytes-lang!!"), s)
	require.False(t, ok)
}
