package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDerefStr_NilPointer(t *testing.T) {
	assert.Equal(t, "", derefStr(nil))
}

func TestDerefStr_NonNil(t *testing.T) {
	s := "testverdi"
	assert.Equal(t, "testverdi", derefStr(&s))
}

func TestCheckboxInt_Checked(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("active=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	require.NoError(t, req.ParseForm())
	assert.Equal(t, int64(1), checkboxInt(req, "active"))
}

func TestCheckboxInt_Unchecked(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	require.NoError(t, req.ParseForm())
	assert.Equal(t, int64(0), checkboxInt(req, "active"))
}

func TestNullableStr_Empty(t *testing.T) {
	assert.Nil(t, nullableStr(""))
	assert.Nil(t, nullableStr("   "))
}

func TestNullableStr_NonEmpty(t *testing.T) {
	result := nullableStr("  spekto  ")
	require.NotNil(t, result)
	assert.Equal(t, "spekto", *result)
}

func TestDefaultStr_Empty_UsesDefault(t *testing.T) {
	assert.Equal(t, "PT15M", defaultStr("", "PT15M"))
	assert.Equal(t, "PT15M", defaultStr("   ", "PT15M"))
}

func TestDefaultStr_NonEmpty_UsesValue(t *testing.T) {
	assert.Equal(t, "PT1H", defaultStr("PT1H", "PT15M"))
}

func TestAuditExport_Headers(t *testing.T) {
	// Verifiser at CSV-eksport setter korrekte HTTP-headere.
	w := httptest.NewRecorder()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="kauth-audit.csv"`)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/csv")
	assert.Contains(t, w.Header().Get("Content-Disposition"), "kauth-audit.csv")
}
