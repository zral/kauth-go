package auth

import (
	"html/template"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Vinkjeller-grenen (020) er låst til tjeneste-ID-en. Golden-filene vokter at
// andre tjenester er uendret; denne vokter at grenen faktisk slår inn, og at
// om-lenken ikke rendres til https:///om når domenet mangler.
func TestLoginTemplate_VinkjellerBranding(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)

	render := func(page, svcID, domain string) string {
		data := testPageData(t, "dark", "nb", "/login?service="+svcID)
		data.Service.ID = svcID
		data.Service.Domain = domain
		var out strings.Builder
		require.NoError(t, tmpl.ExecuteTemplate(&out, page, data))
		return out.String()
	}

	login := render("login.html", "vinkjeller", "kjeller.lilleklo.work")
	assert.Contains(t, login, "Space Grotesk")
	assert.Contains(t, login, `<a href="https://kjeller.lilleklo.work/om" class="about">Hva er Vinkjeller? →</a>`)

	assert.Contains(t, render("magic-login.html", "vinkjeller", "kjeller.lilleklo.work"), "Space Grotesk")

	assert.NotContains(t, render("login.html", "vinkjeller", ""), `class="about"`)

	other := render("login.html", "test", "test.local")
	assert.NotContains(t, other, "Space Grotesk")
	assert.NotContains(t, other, `class="about"`)
}
