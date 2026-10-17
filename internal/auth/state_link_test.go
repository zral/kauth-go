package auth

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseState_Link(t *testing.T) {
	fixClock(t, stateT0)
	iat := iatStr(0)
	base := "klarsyn:n1:" + iat + ":idp=acme"
	tests := []struct {
		name    string
		payload string
		ok      bool
		link    int64
	}{
		{"gyldig", base + ":link=7", true, 7},
		{"stor id", base + ":link=9223372036854775807", true, 9223372036854775807},
		{"tjeneste-ID med kolon", "a:b:n1:" + iat + ":idp=acme:link=3", true, 3},
		{"link uten idp", "klarsyn:n1:" + iat + ":link=7", false, 0},
		{"link uten idp, med admin", "klarsyn:n1:" + iat + ":admin:link=7", false, 0},
		{"id null", base + ":link=0", false, 0},
		{"id negativ", base + ":link=-1", false, 0},
		{"id tom", base + ":link=", false, 0},
		{"id ikke numerisk", base + ":link=abc", false, 0},
		{"id med pluss", base + ":link=+5", false, 0},
		{"id med innledende null", base + ":link=007", false, 0},
		{"id for stor", base + ":link=9223372036854775808", false, 0},
		{"to link-suffikser", base + ":link=1:link=2", false, 0},
		{"ekstra segment etter link", base + ":link=1:x", false, 0},
		{"ekstra segment mellom", base + ":x:link=1", false, 0},
		{"link foran idp", "klarsyn:n1:" + iat + ":link=1:idp=acme", false, 0},
		{"to idp-suffikser", "klarsyn:n1:" + iat + ":idp=a:idp=b:link=1", false, 0},
		{"admin sammen med link", "klarsyn:n1:" + iat + ":admin:idp=acme:link=1", false, 0},
		{"admin bak link", base + ":link=1:admin", false, 0},
		{"link uten iat", "klarsyn:n1:idp=acme:link=1", false, 0},
		{"ugyldig slug", "klarsyn:n1:" + iat + ":idp=Acme:link=1", false, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, ok := parseState(stateSecret, rawState(tc.payload))
			require.Equal(t, tc.ok, ok)
			if !ok {
				return
			}
			require.Equal(t, tc.link, c.Link)
			require.Equal(t, "acme", c.IDP)
			require.False(t, c.Admin)
		})
	}
}

func TestSignLinkState_RoundtripAndRejectedByVerifyState(t *testing.T) {
	fixClock(t, stateT0)
	s := signLinkState(stateSecret, "a:b", "n9", "acme", 42)
	c, ok := parseState(stateSecret, s)
	require.True(t, ok)
	require.Equal(t, stateClaims{ServiceID: "a:b", Nonce: "n9", IDP: "acme", Link: 42}, c)

	_, ok = VerifyState(stateSecret, s)
	require.False(t, ok, "VerifyState skal avvise link-state")
}

func TestSignIDPState_HasNoLink(t *testing.T) {
	fixClock(t, stateT0)
	c, ok := parseState(stateSecret, signIDPState(stateSecret, "k", "n", "acme"))
	require.True(t, ok)
	require.Zero(t, c.Link, "vanlig idp-state skal aldri bære link")
}

func TestSignLinkState_WrongSecretAndTamperedID(t *testing.T) {
	fixClock(t, stateT0)
	_, ok := parseState([]byte("annen-hemmelighet-32-bytes-lang!!"), signLinkState(stateSecret, "k", "n", "acme", 1))
	require.False(t, ok)
	// Samme MAC, annen id: signaturen dekker id-en.
	good := tamperLinkID(t, signLinkState(stateSecret, "k", "n", "acme", 1), "link=1", "link=2")
	_, ok = parseState(stateSecret, good)
	require.False(t, ok)
}

// tamperLinkID bytter tekst i payloaden men beholder den gamle MAC-en.
func tamperLinkID(t *testing.T, state, from, to string) string {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(state)
	require.NoError(t, err)
	raw := string(b)
	require.Contains(t, raw, from)
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(raw, from, to, 1)))
}
