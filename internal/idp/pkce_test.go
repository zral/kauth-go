package idp

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPKCEVerifier(t *testing.T) {
	s1, s2 := []byte("hemmelighet-en-som-er-lang-nok-32"), []byte("hemmelighet-to-som-er-lang-nok-32")
	v := PKCEVerifier(s1, "state-a")
	require.Len(t, v, 43)
	require.Regexp(t, regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`), v)
	require.Equal(t, v, PKCEVerifier(s1, "state-a"))
	require.NotEqual(t, v, PKCEVerifier(s1, "state-b"))
	require.NotEqual(t, v, PKCEVerifier(s2, "state-a"))
}

func TestPKCEVerifier_Golden(t *testing.T) {
	require.Equal(t, "K5INrI4CON6WgV0sS0MnGtQCidQ2iVQIbPbqzhJmEaA", PKCEVerifier([]byte("0123456789abcdef0123456789abcdef"), "state-1"))
}
