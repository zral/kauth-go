package i18n

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTaglinesComplete er samme sikkerhetsnett som TestCatalogComplete, men for
// tjenestenes egne budskap: legger noen til en tjeneste uten å oversette den,
// feiler denne i stedet for at login-siden viser norsk tekst på tysk.
func TestTaglinesComplete(t *testing.T) {
	require.NotEmpty(t, taglines, "taglines-katalogen er tom")

	for serviceID, perLocale := range taglines {
		for _, locale := range supported {
			assert.NotEmpty(t, perLocale[locale],
				"tjeneste %s mangler tagline for %s", serviceID, locale)
		}
		assert.Len(t, perLocale, len(supported),
			"tjeneste %s har en locale som ikke er støttet", serviceID)
	}
}

func TestTagline(t *testing.T) {
	assert.Equal(t, "Logg inn for å administrere dine arrangementer", Tagline("spekto", "nb"))
	assert.Equal(t, "Sign in to manage your events", Tagline("spekto", "en"))
	assert.Equal(t, "Melden Sie sich an, um Ihre Veranstaltungen zu verwalten", Tagline("spekto", "de"))
}

// Ukjent tjeneste gir tom streng, ikke en annen tjenestes tagline — handleren
// faller da tilbake til services.tagline fra databasen.
func TestTagline_UnknownServiceIsEmpty(t *testing.T) {
	assert.Empty(t, Tagline("finnes-ikke", "de"))
	assert.Empty(t, Tagline("", "nb"))
}

// Kjent tjeneste med ukjent locale faller til engelsk, samme regel som Get.
func TestTagline_UnknownLocaleFallsBackToEnglish(t *testing.T) {
	assert.Equal(t, Tagline("spekto", Fallback), Tagline("spekto", "fr"))
}

// Alle tjenestene som finnes i prod må være dekket — ellers får de norsk
// tagline på tysk side via DB-fallbacken uten at noe varsler om det.
func TestTaglines_CoversProductionServices(t *testing.T) {
	for _, id := range []string{"spekto", "wspekto", "klarsyn", "analyse", "vinkjeller"} {
		_, ok := taglines[id]
		assert.True(t, ok, "tjeneste %s mangler i taglines-katalogen", id)
	}
}
