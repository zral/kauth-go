package i18n

// taglines er tjenestenes egne budskap på login-siden, nøklet på tjeneste-ID.
//
// Disse ligger i koden framfor i services-tabellen fordi de er innhold, ikke
// konfigurasjon: markedsføringstekst på tre språk må kunne leses og revideres
// som en helhet, og TestTaglinesComplete gjør det til en byggefeil å legge til
// en tjeneste uten å oversette den. Et tomt admin-felt hadde vært usynlig til
// noen oppdaget at den tyske siden mangler undertittel.
//
// En tjeneste uten oppføring her faller tilbake til services.tagline — se
// Tagline og ServeLogin. Det er samme fallback-hierarki som locale-oppslaget
// selv bruker, ikke to konkurrerende kilder til samme sannhet.
var taglines = map[string]map[string]string{
	"spekto": {
		"nb": "Logg inn for å administrere dine arrangementer",
		"en": "Sign in to manage your events",
		"de": "Melden Sie sich an, um Ihre Veranstaltungen zu verwalten",
	},
	"wspekto": {
		"nb": "Fra utløser til redaksjon på sekunder",
		"en": "From trigger to newsroom in seconds",
		"de": "Vom Auslöser zur Redaktion in Sekunden",
	},
	"klarsyn": {
		"nb": "Innsikt som skaper forsprang",
		"en": "Insight that puts you ahead",
		"de": "Einblicke, die Vorsprung schaffen",
	},
	"analyse": {
		"nb": "Innsikt som skaper forsprang",
		"en": "Insight that puts you ahead",
		"de": "Einblicke, die Vorsprung schaffen",
	},
	"vinkjeller": {
		"nb": "Din personlige vinsamling",
		"en": "Your personal wine collection",
		"de": "Ihre persönliche Weinsammlung",
	},
}

// Tagline returnerer tjenestens budskap på valgt språk, eller tom streng hvis
// tjenesten ikke er oversatt. Kalleren avgjør hva tom streng skal bety —
// ServeLogin bruker services.tagline da, slik at en nyopprettet tjeneste viser
// noe uten at koden må deployes på nytt.
func Tagline(serviceID, locale string) string {
	perLocale, ok := taglines[serviceID]
	if !ok {
		return ""
	}
	if s := perLocale[locale]; s != "" {
		return s
	}
	return perLocale[Fallback]
}
