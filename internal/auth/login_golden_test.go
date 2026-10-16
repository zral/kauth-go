package auth

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Golden-filene er rendret fra malen slik den var før 015 F5. Uten
// leverandører skal siden fortsatt komme ut byte-for-byte likt (K1).
// Regenerer med KAUTH_UPDATE_GOLDEN=1 bare når login-malen endres med vilje.
func TestLoginTemplate_GoldenWithoutProviders(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)
	for _, theme := range []string{"light", "dark"} {
		for _, locale := range []string{"nb", "en", "de"} {
			for _, svcID := range []string{"test", "spekto"} {
				name := fmt.Sprintf("login_%s_%s_%s.golden.html", theme, locale, svcID)
				t.Run(name, func(t *testing.T) {
					data := testPageData(t, theme, locale, "/login?service="+svcID)
					data.Service.ID = svcID
					var out strings.Builder
					require.NoError(t, tmpl.ExecuteTemplate(&out, "login.html", data))
					path := filepath.Join("testdata", name)
					if os.Getenv("KAUTH_UPDATE_GOLDEN") == "1" {
						require.NoError(t, os.WriteFile(path, []byte(out.String()), 0o644))
						return
					}
					want, err := os.ReadFile(path)
					require.NoError(t, err)
					require.Equal(t, string(want), out.String())
				})
			}
		}
	}
}

// Alle metoder av og en feilmelding satt: en annen kodesti i malen enn
// standardvarianten, og den skal også være uendret uten leverandører.
func TestLoginTemplate_GoldenAllMethodsOffWithError(t *testing.T) {
	dir := "../../templates"
	if d := os.Getenv("KAUTH_GOLDEN_TMPL_DIR"); d != "" {
		dir = d
	}
	tmpl, err := template.ParseGlob(dir + "/*.html")
	require.NoError(t, err)
	data := testPageData(t, "light", "nb", "/login?service=test&error=login_failed")
	data.Service.AuthGoogle = 0
	data.Service.AuthMicrosoft = 0
	data.Service.AuthMagicLink = 0
	data.Service.AuthPassword = 0
	data.PasswordLoginEnabled = false
	data.Error = "login_failed"
	var out strings.Builder
	require.NoError(t, tmpl.ExecuteTemplate(&out, "login.html", data))
	path := filepath.Join("testdata", "login_light_nb_test_alloff_error.golden.html")
	if os.Getenv("KAUTH_UPDATE_GOLDEN") == "1" {
		require.NoError(t, os.WriteFile(path, []byte(out.String()), 0o644))
		return
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, string(want), out.String())
}
