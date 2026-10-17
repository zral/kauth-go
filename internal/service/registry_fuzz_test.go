package service

import (
	"regexp"
	"strconv"
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
		return base + "\u200b"
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

// fuzzAllowedByService er den faste fasiten for hva som er registrert, uavhengig
// av koden som testes.
var fuzzAllowedByService = map[string][]string{
	"spekto":  fuzzCallbacks,
	"klarsyn": {"https://klarsyn.net/cb"},
}

var fuzzUserinfoRe = regexp.MustCompile(`^[A-Za-z0-9._~%!$&'()*+,;=:-]*$`)

// FuzzResolveRedirectURI: redirect_uri velger tjeneste og autoriserer aldri
// redirect. Egenskaper: (a) userinfo, port og \, tab og %2e i verten flytter
// aldri valget til en annen tjeneste enn den uten dem (nil er greit); (b) når
// Resolve velger en tjeneste, godtar IsAllowedCallback input bare hvis den er
// eksakt en av tjenestens faste callbacks.
func FuzzResolveRedirectURI(f *testing.F) {
	f.Add("https://evil.example/cb", uint8(0), "user")
	f.Add("https://spekto.live@evil.example/cb", uint8(1), "443")
	f.Add("https://app.spekto.live/cb", uint8(2), "x")
	f.Add("https://app.spekto.live/cb", uint8(3), "")
	f.Add("https://test.spekto.live/cb?x=1", uint8(4), "evil.example")
	f.Add("https://klarsyn.net/auth/callback", uint8(5), "")

	reg, _ := fuzzRegistry()
	f.Fuzz(func(t *testing.T, uri string, kind uint8, extra string) {
		for _, c := range []string{uri, mutateURI(fuzzCallbacks[int(kind)%len(fuzzCallbacks)], kind, extra)} {
			svc := reg.Resolve("", "", c)
			if svc == nil {
				continue
			}
			if got := reg.IsAllowedCallback(svc, c); got {
				ok := false
				for _, cb := range fuzzAllowedByService[svc.ID] {
					if c == cb {
						ok = true
					}
				}
				if !ok {
					t.Fatalf("IsAllowedCallback godtok %q for %s, ikke i fast liste", c, svc.ID)
				}
			}
		}

		// (a)
		base := fuzzCallbacks[int(kind)%len(fuzzCallbacks)]
		want := reg.Resolve("", "", base)
		if want == nil {
			t.Fatalf("grunn-callback %q løser ikke til noen tjeneste", base)
		}
		variants := []string{
			strings.Replace(base, "://", "://\t\\x@", 1),
			strings.Replace(base, "://", "://user:pw@", 1),
			strings.Replace(base, "/", "\\/", 3),
			strings.Replace(base, "spekto", "%2espekto", 1),
		}
		if fuzzUserinfoRe.MatchString(extra) {
			variants = append(variants,
				strings.Replace(base, "://", "://"+extra+"@", 1),
				strings.Replace(base, "://", "://"+extra+":"+extra+"@", 1))
		}
		if _, err := strconv.Atoi(extra); err == nil {
			variants = append(variants, strings.Replace(base, "/cb", ":"+extra+"/cb", 1))
		}
		variants = append(variants, strings.Replace(base, ".", "\t.", 1), strings.Replace(base, ".", "%2e", 1))
		for _, v := range variants {
			if got := reg.Resolve("", "", v); got != nil && got.ID != want.ID {
				t.Fatalf("Resolve(%q) = %s, men %q gir %s", v, got.ID, base, want.ID)
			}
		}
	})
}
