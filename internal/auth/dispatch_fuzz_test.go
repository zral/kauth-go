package auth

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
)

// FuzzDispatchRedirectTarget dekker målvalget på nivå 1 i /dispatch og i
// logout: verdien fra den usignerte redirect_uri-cookien, lest av
// readRedirectCookie og vurdert av IsAllowedCallback mot alle tjenester.
// Koden har bevisst ingen intern-sti-gren, så et godtatt mål er bare en
// registrert callback, og den ferdige redirect-URL-en peker på samme vert.
func FuzzDispatchRedirectTarget(f *testing.F) {
	callbacks := []string{"https://app.spekto.live/cb", "https://klarsyn.net/auth/callback"}
	f.Add("https://app.spekto.live/cb")
	f.Add("%22https%3A%2F%2Fapp.spekto.live%2Fcb%22")
	f.Add("/\\evil.example")
	f.Add("//evil.example")
	f.Add("/internal/path")
	f.Add("https://app.spekto.live@evil.example/cb")
	f.Add("https:%2F%2Fevil.example")
	f.Add("javascript:alert(1)")

	svcs := []*gen.Service{
		{ID: "spekto", CallbackUrl: callbacks[0]},
		{ID: "klarsyn", CallbackUrl: callbacks[1]},
	}
	registry := &service.Registry{}

	f.Fuzz(func(t *testing.T, cookie string) {
		r, _ := http.NewRequest("GET", "/dispatch", nil)
		r.Header.Set("Cookie", "redirect_uri="+cookie)
		got := readRedirectCookie(r)
		if got == "" {
			return
		}
		var accepted bool
		for _, s := range svcs {
			if registry.IsAllowedCallback(s, got) {
				accepted = true
			}
		}
		if !accepted {
			return
		}
		exact := false
		for _, cb := range callbacks {
			if got == cb {
				exact = true
			}
		}
		if !exact {
			t.Fatalf("godtatt mål %q er ikke en registrert callback (cookie %q)", got, cookie)
		}
		out := appendTokenAndRT(got, "tok", "rt")
		u, err := url.Parse(out)
		if err != nil {
			t.Fatalf("ferdig redirect %q kan ikke parses: %v", out, err)
		}
		want, _ := url.Parse(got)
		if u.Host != want.Host || u.Scheme != "https" || strings.HasPrefix(out, "//") || strings.HasPrefix(out, "/") {
			t.Fatalf("redirect %q peker ikke på callback-verten %q", out, want.Host)
		}
	})
}
