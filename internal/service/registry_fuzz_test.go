package service

import (
	"net/url"
	"strings"
	"testing"

	"github.com/zral/kauth-go/internal/db/gen"
)

var fuzzCallbacks = []string{
	"https://app.spekto.live/cb",
	"https://test.spekto.live/cb?x=1",
	"https://klarsyn.net/auth/callback",
}

func fuzzRegistry() (*Registry, *gen.Service) {
	svc := gen.Service{
		ID:          "spekto",
		Domain:      "spekto.live",
		CallbackUrl: fuzzCallbacks[0] + ", " + fuzzCallbacks[1] + "," + fuzzCallbacks[2],
	}
	other := gen.Service{ID: "klarsyn", Domain: "klarsyn.net", CallbackUrl: "https://klarsyn.net/cb"}
	r := &Registry{}
	r.cache = []gen.Service{svc, other}
	return r, &svc
}

// mutateURI lager en nær-treff av en gyldig callback. Fuzzeren velger
// mutasjonstype, så de kjente omgåelsene (case, /, #, ?, @, \, unicode,
// prosentkoding, ..) alltid er med uten å vente på at motoren finner dem.
func mutateURI(base string, kind uint8, extra string) string {
	switch kind % 12 {
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
		return strings.Replace(base, "/cb", "/%63b", 1)
	case 8:
		return strings.Replace(base, "/cb", "/../cb", 1)
	case 9:
		return " " + base
	case 10:
		return base + "​"
	default:
		return strings.Replace(base, "https://", "https://"+extra, 1)
	}
}

func FuzzIsAllowedCallback(f *testing.F) {
	for i, cb := range fuzzCallbacks {
		f.Add(cb, uint8(i), "evil.example")
	}
	f.Add("https://app.spekto.live/cb", uint8(2), "")
	f.Add("https://app.spekto.live/cb", uint8(4), "evil.example")
	f.Add("https://app.spekto.live/cb", uint8(5), "")
	f.Add("//evil.example", uint8(6), "")
	f.Add("", uint8(0), "")

	reg, svc := fuzzRegistry()
	f.Fuzz(func(t *testing.T, uri string, kind uint8, extra string) {
		candidates := []string{uri}
		for _, cb := range fuzzCallbacks {
			candidates = append(candidates, mutateURI(cb, kind, extra))
		}
		for _, c := range candidates {
			want := false
			for _, cb := range fuzzCallbacks {
				if c == cb {
					want = true
				}
			}
			if got := reg.IsAllowedCallback(svc, c); got != want {
				t.Fatalf("IsAllowedCallback(%q) = %v, forventet %v (eksakt lik registrert)", c, got, want)
			}
		}
	})
}

// FuzzResolveRedirectURI sjekker at redirect_uri alene bare kan velge en
// tjeneste hvis URL-ens faktiske vert (slik url.Parse leser den, ikke
// teksten før en @) er tjenestens domene eller et underdomene av det.
func FuzzResolveRedirectURI(f *testing.F) {
	for _, cb := range fuzzCallbacks {
		f.Add(cb, uint8(0), "")
	}
	f.Add("https://spekto.live@evil.example/cb", uint8(0), "")
	f.Add("https://evil.example\\@spekto.live/cb", uint8(0), "")
	f.Add("https://evil.example/.spekto.live", uint8(0), "")

	reg, _ := fuzzRegistry()
	f.Fuzz(func(t *testing.T, uri string, kind uint8, extra string) {
		candidates := []string{uri}
		for _, cb := range fuzzCallbacks {
			candidates = append(candidates, mutateURI(cb, kind, extra))
		}
		for _, c := range candidates {
			got := reg.Resolve("", "", c)
			if got == nil {
				continue
			}
			u, err := url.Parse(c)
			if err != nil || u.Host == "" {
				t.Fatalf("Resolve(%q) ga %s uten gyldig vert", c, got.ID)
			}
			h := strings.ToLower(u.Host)
			d := strings.ToLower(got.Domain)
			if h != d && !strings.HasSuffix(h, "."+d) {
				t.Fatalf("Resolve(%q) ga %s (domene %s), men verten er %q", c, got.ID, got.Domain, h)
			}
		}
	})
}
