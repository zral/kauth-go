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
	callbacks := []string{"https://app.spekto.live/cb", "https://test.spekto.live/cb?x=1", "https://klarsyn.net/auth/callback", "https://klarsyn.net/cb"}
	f.Add("https://app.spekto.live/cb", uint8(0), "")
	f.Add("%22https%3A%2F%2Fapp.spekto.live%2Fcb%22", uint8(1), "evil.example")
	f.Add("/\\evil.example", uint8(1), "evil.example")
	f.Add("//evil.example", uint8(1), "evil.example")
	f.Add("/internal/path", uint8(1), "evil.example")
	f.Add("https://app.spekto.live@evil.example/cb", uint8(1), "evil.example")
	f.Add("https:%2F%2Fevil.example", uint8(1), "evil.example")
	f.Add("javascript:alert(1)", uint8(1), "evil.example")

	svcs := []*gen.Service{
		{ID: "spekto", CallbackUrl: callbacks[0] + ", " + callbacks[1]},
		{ID: "klarsyn", CallbackUrl: callbacks[2] + "," + callbacks[3]},
	}
	registry := &service.Registry{}

	f.Fuzz(func(t *testing.T, cookie string, kind uint8, extra string) {
		cb := callbacks[int(kind)%len(callbacks)]
		for _, c := range []string{cookie, url.QueryEscape(mutateCallback(cb, kind, extra))} {
			checkDispatchTarget(t, c, callbacks, svcs, registry)
		}
	})
}

func mutateCallback(base string, kind uint8, extra string) string {
	switch kind % 10 {
	case 0:
		return strings.ToUpper(base)
	case 1:
		return base + "/"
	case 2:
		return base + "#" + extra
	case 3:
		return base + "?" + extra
	case 4:
		return strings.Replace(base, "://", "://"+extra+"@", 1)
	case 5:
		return strings.Replace(base, "://", "://x\\@", 1)
	case 6:
		return base + extra
	case 7:
		return strings.Replace(base, "/cb", "/../cb", 1)
	case 8:
		return " " + base + "\u200b"
	default:
		return base
	}
}

func checkDispatchTarget(t *testing.T, cookie string, callbacks []string, svcs []*gen.Service, registry *service.Registry) {
	{
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
	}
}
