package auth

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// subject() er siste vern for id-en uavhengig av JSON-dekoderen: bare kanonisk
// heltallstekst > 0 blir subject, så «007» og «+5» aldri kan bli en annen brukers id.
func TestGhUserSubject(t *testing.T) {
	for in, want := range map[string]string{"1": "1", "9223372036854775807": "9223372036854775807"} {
		got, err := ghUser{ID: json.Number(in)}.subject()
		require.NoError(t, err, in)
		require.Equal(t, want, got)
	}
	for _, in := range []string{"", "0", "-1", "007", "+5", "1.0", "1e3", "abc", " 5", "9223372036854775808"} {
		_, err := ghUser{ID: json.Number(in)}.subject()
		require.ErrorIs(t, err, errGHMissingID, in)
	}
}
