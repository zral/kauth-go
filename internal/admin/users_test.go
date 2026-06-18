package admin

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCsvEsc_CleanString_Unchanged(t *testing.T) {
	assert.Equal(t, "hei verden", csvEsc("hei verden"))
}

func TestCsvEsc_FormulaPrefix_EscapedWithApostrophe(t *testing.T) {
	cases := []string{"=SUM(A1)", "+1", "-1", "@cmd", "\tcell", "\rcell"}
	for _, c := range cases {
		result := csvEsc(c)
		assert.Equal(t, '\'', rune(result[0]), "forventet apostrofprefix for input: %q", c)
	}
}

func TestCsvEsc_CommaInString_Quoted(t *testing.T) {
	assert.Equal(t, `"Ola, Nordmann"`, csvEsc("Ola, Nordmann"))
}

func TestCsvEsc_QuoteInString_Doubled(t *testing.T) {
	assert.Equal(t, `"Han sa ""hei"""`, csvEsc(`Han sa "hei"`))
}

func TestCsvEsc_NewlineInString_Quoted(t *testing.T) {
	assert.Equal(t, "\"linje1\nlinje2\"", csvEsc("linje1\nlinje2"))
}

func TestCsvEsc_EmptyString_Unchanged(t *testing.T) {
	assert.Equal(t, "", csvEsc(""))
}
