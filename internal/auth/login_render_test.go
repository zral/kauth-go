package auth

import (
	"html/template"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/i18n"
)

// testLoginService har alle fire innloggingsmetoder på, slik at rendringen
// treffer hver gren i templaten og ingen oversatt streng blir stående
// uprøvd bak en {{if}}.
func testLoginService(theme string) *gen.Service {
	tagline := "Test-tjeneste"
	return &gen.Service{
		ID:             "test",
		DisplayName:    "Testify",
		Tagline:        &tagline,
		Domain:         "test.local",
		CallbackUrl:    "https://test.local/callback",
		Theme:          theme,
		AccentColor:    "#2563EB",
		EmailFromName:  "Test",
		AuthGoogle:     1,
		AuthMicrosoft:  1,
		AuthMagicLink:  1,
		AuthPassword:   1,
		JwtCookieName:  "auth_token",
		AccessTokenTtl: "PT15M",
		Active:         1,
	}
}

// testPageData bygger template-data slik ServeLogin gjør det.
func testPageData(t *testing.T, theme, locale, rawURL string) LoginPageData {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)

	svc := testLoginService(theme)
	bodyCss, beforeCss := buildBgCSS(svc.Theme, svc.BgImage, svc.BgCss)
	return LoginPageData{
		Service:     svc,
		BodyBgCSS:   bodyCss,
		BeforeBgCSS: beforeCss,
		Locale:      locale,
		T:           i18n.Get(locale),
		Languages:   i18n.Links(locale, u),
	}
}

// TestLoginTemplate_RendersInAllLocales fanger feltnavn-typo i templaten —
// den ene feilklassen struct-katalogen ikke fanger ved kompilering.
func TestLoginTemplate_RendersInAllLocales(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)

	want := map[string]string{
		"en": "Continue with Google",
		"nb": "Fortsett med Google",
		"de": "Mit Google fortfahren",
	}

	for _, theme := range []string{"light", "dark"} {
		for _, locale := range []string{"en", "nb", "de"} {
			t.Run(theme+"/"+locale, func(t *testing.T) {
				data := testPageData(t, theme, locale, "/login?service=test")

				var out strings.Builder
				require.NoError(t, tmpl.ExecuteTemplate(&out, "login.html", data))

				html := out.String()
				assert.Contains(t, html, want[locale])
				assert.Contains(t, html, `<html lang="`+locale+`">`)
				// Magic-link-knappen må bære språket videre. Sjekk hele
				// href-en, ikke bare "lang=<locale>" — den strengen finnes
				// i språkvelgeren uansett locale og ville gjort testen blind.
				assert.Contains(t, html, "/magic-login?service=test&amp;lang="+locale)
			})
		}
	}
}

func TestLoginTemplate_ShowsLanguageSwitcher(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)

	data := testPageData(t, "light", "de", "/login?service=test")
	var out strings.Builder
	require.NoError(t, tmpl.ExecuteTemplate(&out, "login.html", data))

	html := out.String()
	// Aktivt språk vises uten lenke, de to andre som lenker.
	assert.Contains(t, html, ">DE<")
	assert.Contains(t, html, "Norsk")
	assert.Contains(t, html, "English")
	assert.Contains(t, html, "lang=nb")
	assert.Contains(t, html, "lang=en")
}

func TestLoginTemplate_TranslatesErrorCodes(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)

	data := testPageData(t, "light", "de", "/login?service=test")
	data.Error = "access_denied"

	var out strings.Builder
	require.NoError(t, tmpl.ExecuteTemplate(&out, "login.html", data))
	assert.Contains(t, out.String(), "Zugriff verweigert.")
}
