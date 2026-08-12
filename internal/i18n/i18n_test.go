package i18n

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCatalogComplete er sikkerhetsnettet mot halvferdige språk: legger noen
// til et felt i Strings uten å oversette det, feiler denne i stedet for at
// login-siden viser blankt i prod.
func TestCatalogComplete(t *testing.T) {
	for _, locale := range []string{"en", "nb", "de"} {
		s, ok := catalog[locale]
		require.True(t, ok, "locale %s mangler i katalogen", locale)

		v := reflect.ValueOf(s)
		typ := v.Type()
		for i := 0; i < typ.NumField(); i++ {
			assert.NotEmpty(t, v.Field(i).String(),
				"locale %s mangler oversettelse for felt %s", locale, typ.Field(i).Name)
		}
	}
}

// TestCatalogHasNoExtraLocales fanger en locale som er lagt til i katalogen
// men ikke i supported-listen (Task 2) eller i språkvelgeren.
func TestCatalogHasNoExtraLocales(t *testing.T) {
	assert.Len(t, catalog, 3)
}

func TestMailBodyHasOnePlaceholder(t *testing.T) {
	for locale, s := range catalog {
		assert.Equal(t, 1, strings.Count(s.MailBody, "{link}"),
			"locale %s: MailBody må ha nøyaktig én {link}", locale)
		assert.NotContains(t, s.MailBody, "%s",
			"locale %s: bruk {link}, ikke %%s — go vet flagger ikke-konstante format-strenger", locale)
	}
}

func TestGet(t *testing.T) {
	assert.Equal(t, "Fortsett med Google", Get("nb").ContinueWithGoogle)
	assert.Equal(t, "Mit Google fortfahren", Get("de").ContinueWithGoogle)
	assert.Equal(t, "Continue with Google", Get("en").ContinueWithGoogle)
}

func TestGet_UnknownLocaleFallsBackToEnglish(t *testing.T) {
	assert.Equal(t, catalog[Fallback], Get("fr"))
	assert.Equal(t, catalog[Fallback], Get(""))
}
