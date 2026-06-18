package admin

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCsvEsc_Empty(t *testing.T) {
	assert.Equal(t, "", csvEsc(""))
}

func TestCsvEsc_Clean(t *testing.T) {
	assert.Equal(t, "hello", csvEsc("hello"))
}

func TestCsvEsc_Comma(t *testing.T) {
	// csv.Writer håndterer quoting — csvEsc gjør ingenting med komma.
	assert.Equal(t, "a,b", csvEsc("a,b"))
}

func TestCsvEsc_Quote(t *testing.T) {
	// csv.Writer håndterer quoting — csvEsc gjør ingenting med anførselstegn.
	assert.Equal(t, `he said "hi"`, csvEsc(`he said "hi"`))
}

func TestCsvEsc_Newline(t *testing.T) {
	// csv.Writer håndterer quoting — csvEsc gjør ingenting med newline.
	assert.Equal(t, "line1\nline2", csvEsc("line1\nline2"))
}

func TestCsvEsc_FormulaPrefix(t *testing.T) {
	assert.Equal(t, "'=A1", csvEsc("=A1"))
}

func TestCsvEsc_CarriageReturnPrefix(t *testing.T) {
	assert.Equal(t, "'\rcell", csvEsc("\rcell"))
}

func TestCsvEsc_TabPrefix(t *testing.T) {
	assert.Equal(t, "'\tcell", csvEsc("\tcell"))
}

func TestCsvEsc_PlusPrefix(t *testing.T) {
	assert.Equal(t, "'+1", csvEsc("+1"))
}
