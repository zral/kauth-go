package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseState_IDP(t *testing.T) {
	fixClock(t, stateT0)
	iat := iatStr(0)
	tests := []struct {
		name    string
		payload string
		ok      bool
		svc     string
		nonce   string
		slug    string
		admin   bool
	}{
		{"vanlig idp", "klarsyn:n1:" + iat + ":idp=acme", true, "klarsyn", "n1", "acme", false},
		{"slug med tall og bindestrek", "klarsyn:n1:" + iat + ":idp=a-1", true, "klarsyn", "n1", "a-1", false},
		{"tjeneste-ID med kolon", "a:b:n1:" + iat + ":idp=acme", true, "a:b", "n1", "acme", false},
		{"tjeneste-ID ligner idp-suffiks", "x:idp=evil:n1:" + iat + ":idp=acme", true, "x:idp=evil", "n1", "acme", false},
		{"tjeneste-ID ligner idp, vanlig state", "x:idp=evil:n1:" + iat, true, "x:idp=evil", "n1", "", false},
		{"idp sammen med admin (admin foran)", "klarsyn:n1:" + iat + ":admin:idp=acme", false, "", "", "", false},
		{"idp sammen med admin (admin bak)", "klarsyn:n1:" + iat + ":idp=acme:admin", false, "", "", "", false},
		{"tom slug", "klarsyn:n1:" + iat + ":idp=", false, "", "", "", false},
		{"slug med store bokstaver", "klarsyn:n1:" + iat + ":idp=Acme", false, "", "", "", false},
		{"slug med kolon", "klarsyn:n1:" + iat + ":idp=a:b", false, "", "", "", false},
		{"slug med understrek", "klarsyn:n1:" + iat + ":idp=a_b", false, "", "", "", false},
		{"slug for lang", "klarsyn:n1:" + iat + ":idp=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false, "", "", "", false},
		{"to idp-suffikser", "klarsyn:n1:" + iat + ":idp=a:idp=b", false, "", "", "", false},
		{"idp uten iat", "klarsyn:n1:idp=acme", false, "", "", "", false},
		{"admin vanlig", "klarsyn:n1:" + iat + ":admin", true, "klarsyn", "n1", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, ok := parseState(stateSecret, rawState(tc.payload))
			require.Equal(t, tc.ok, ok)
			if !ok {
				return
			}
			require.Equal(t, tc.svc, c.ServiceID)
			require.Equal(t, tc.nonce, c.Nonce)
			require.Equal(t, tc.slug, c.IDP)
			require.Equal(t, tc.admin, c.Admin)
		})
	}
}

func TestSignIDPState_RoundtripAndRejectedByVerifyState(t *testing.T) {
	fixClock(t, stateT0)
	s := signIDPState(stateSecret, "a:b", "n9", "acme")
	c, ok := parseState(stateSecret, s)
	require.True(t, ok)
	require.Equal(t, stateClaims{ServiceID: "a:b", Nonce: "n9", IDP: "acme"}, c)

	_, ok = VerifyState(stateSecret, s)
	require.False(t, ok, "VerifyState skal avvise IDP-state")

	_, ok = VerifyState(stateSecret, SignState(stateSecret, "klarsyn", "n"))
	require.True(t, ok)
}

func TestSignIDPState_WrongSecretRejected(t *testing.T) {
	fixClock(t, stateT0)
	_, ok := parseState([]byte("annen-hemmelighet-32-bytes-lang!!"), signIDPState(stateSecret, "k", "n", "acme"))
	require.False(t, ok)
}
