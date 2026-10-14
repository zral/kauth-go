package auth

import (
	"net/http/httptest"
	"testing"

	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
)

func socialFixture() *service.Registry {
	h := func(s string) *string { return &s }
	return service.NewRegistryForTest([]gen.Service{
		{ID: "klarsyn", AuthHost: h("auth.klarsyn.net"), Domain: "klarsyn.net"},
		{ID: "analyse", Domain: "analyse.klarsyn.net"},
		{ID: "spekto", AuthHost: h("auth.spekto.live"), Domain: "spekto.live"},
	})
}

func TestResolveSocialService(t *testing.T) {
	reg := socialFixture()
	cases := []struct{ host, query, want string }{
		{"auth.klarsyn.net", "", "klarsyn"},
		// Undertjeneste uten egen auth_host: ?service= vinner over hosten.
		{"auth.klarsyn.net", "?service=analyse", "analyse"},
		{"auth.klarsyn.net", "?service=klarsyn", "klarsyn"},
		// Annen tenant med egen auth_host: hosten vinner.
		{"auth.klarsyn.net", "?service=spekto", "klarsyn"},
		{"AUTH.SPEKTO.LIVE", "?service=spekto", "spekto"},
		{"auth.klarsyn.net", "?service=finnes-ikke", "klarsyn"},
		// Host uten auth_host-match: annen tenant avvises fortsatt (default).
		{"127.0.0.1:8083", "?service=spekto", "klarsyn"},
		{"127.0.0.1:8083", "?service=analyse", "analyse"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/social-login"+c.query, nil)
		r.Host = c.host
		if got := resolveSocialService(reg, r); got == nil || got.ID != c.want {
			t.Errorf("%s%s: fikk %v, ville ha %s", c.host, c.query, got, c.want)
		}
	}
}

func TestResolveRequestedService(t *testing.T) {
	reg := socialFixture()
	cases := []struct{ name, host, id, want string }{
		{"undertjeneste uten auth_host på foreldrehost", "auth.klarsyn.net", "analyse", "analyse"},
		{"tjeneste med nettopp denne auth_host", "auth.spekto.live", "spekto", "spekto"},
		{"tjeneste med annen auth_host gir hostens tjeneste", "auth.klarsyn.net", "spekto", "klarsyn"},
		{"ukjent ID gir hostens tjeneste", "auth.klarsyn.net", "finnes-ikke", "klarsyn"},
		{"ukjent ID og ukjent host gir default", "ukjent.example", "finnes-ikke", "klarsyn"},
		{"fremmed ID på ukjent host gir default", "ukjent.example", "spekto", "klarsyn"},
		{"tom ID gir hosten", "auth.spekto.live", "", "spekto"},
		{"host i store bokstaver matcher", "AUTH.SPEKTO.LIVE", "spekto", "spekto"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/x", nil)
			r.Host = c.host
			if got := resolveRequestedService(reg, r, c.id); got == nil || got.ID != c.want {
				t.Errorf("fikk %v, ville ha %s", got, c.want)
			}
		})
	}
}
