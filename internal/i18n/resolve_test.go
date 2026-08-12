package i18n

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolve(t *testing.T) {
	tests := []struct {
		name   string
		lang   string
		accept string
		want   string
	}{
		{"tom request faller til engelsk", "", "", "en"},
		{"lang-param vinner over header", "de", "nb-NO,nb;q=0.9", "de"},
		{"lang-param er case-insensitiv", "DE", "", "de"},
		{"lang-param tåler whitespace", " nb ", "", "nb"},
		{"ustøttet lang-param faller videre til header", "fr", "de-DE,de;q=0.9", "de"},
		{"ustøttet lang og header faller til engelsk", "fr", "fr-FR,fr;q=0.9", "en"},
		{"region-subtag strippes", "", "de-AT", "de"},
		{"underscore-variant strippes", "", "de_DE", "de"},
		{"nb-NO gir norsk", "", "nb-NO,nb;q=0.9,en;q=0.8", "nb"},
		{"no gir norsk", "", "no", "nb"},
		{"nn gir norsk", "", "nn-NO", "nb"},
		{"q-vekt styrer rekkefølge, ikke posisjon", "", "en;q=0.1,de;q=0.9", "de"},
		{"manglende q betyr full vekt", "", "de,en;q=0.9", "de"},
		{"ugyldig q diskvalifiserer alternativet", "", "de;q=høy,en;q=0.5", "en"},
		{"q=0 diskvalifiserer alternativet", "", "de;q=0,en;q=0.5", "en"},
		{"ukjent språk hoppes over", "", "fr,de;q=0.5", "de"},
		{"lik q beholder rekkefølgen i headeren", "", "de;q=0.5,en;q=0.5", "de"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, Resolve(tc.lang, tc.accept))
		})
	}
}

func TestFromRequest_LangParamWins(t *testing.T) {
	r := httptest.NewRequest("GET", "/login?service=spekto&lang=de", nil)
	r.Header.Set("Accept-Language", "nb-NO,nb;q=0.9")
	assert.Equal(t, "de", FromRequest(r))
}

func TestFromRequest_FallsBackToHeader(t *testing.T) {
	r := httptest.NewRequest("GET", "/login?service=spekto", nil)
	r.Header.Set("Accept-Language", "nb-NO,nb;q=0.9")
	assert.Equal(t, "nb", FromRequest(r))
}

func TestFromRequest_NoSignalsGivesEnglish(t *testing.T) {
	r := httptest.NewRequest("GET", "/login", nil)
	assert.Equal(t, "en", FromRequest(r))
}

// supported må matche katalogen, ellers får vi en språkvelger som peker på
// en locale uten oversettelser.
func TestSupportedMatchesCatalog(t *testing.T) {
	assert.Len(t, supported, len(catalog))
	for _, loc := range supported {
		_, ok := catalog[loc]
		assert.True(t, ok, "supported inneholder %s som ikke finnes i katalogen", loc)
	}
}
