package auth

// BACKLOG F1 / ADN 87 — internal test-fil (package auth, ikke auth_test) fordi
// resolveMagicLinkBaseURL er bevisst unexported (ren intern hjelpefunksjon,
// ikke del av MagicHandlers sitt offentlige API).

import (
	"testing"

	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db/gen"
)

func strPtr(s string) *string { return &s }

func TestResolveMagicLinkBaseURL_UsesServiceAuthHost(t *testing.T) {
	cfg := config.Config{BaseURL: "https://auth.klarsyn.net"}
	svc := &gen.Service{ID: "spekto", AuthHost: strPtr("auth.spekto.live")}

	got := resolveMagicLinkBaseURL(cfg, svc)
	want := "https://auth.spekto.live"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolveMagicLinkBaseURL_FallsBackToConfigWhenAuthHostNil(t *testing.T) {
	cfg := config.Config{BaseURL: "https://auth.klarsyn.net"}
	// Matcher faktisk prod-data: klarsyn er is_default, auth_host er NULL i DB.
	svc := &gen.Service{ID: "klarsyn", AuthHost: nil}

	got := resolveMagicLinkBaseURL(cfg, svc)
	want := "https://auth.klarsyn.net"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolveMagicLinkBaseURL_FallsBackToConfigWhenAuthHostEmpty(t *testing.T) {
	// Syntetisk case, ikke observert i prod-data: nullableStr() konverterer tom
	// streng til NULL ved lagring, så denne verdien kan i praksis aldri komme fra
	// DB-en (analyse.auth_host er faktisk NULL, dekket av testen over). Testet
	// likevel for ren gren-dekning av selve funksjonens tomstreng-sjekk.
	cfg := config.Config{BaseURL: "https://auth.klarsyn.net"}
	svc := &gen.Service{ID: "analyse", AuthHost: strPtr("")}

	got := resolveMagicLinkBaseURL(cfg, svc)
	want := "https://auth.klarsyn.net"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolveMagicLinkBaseURL_FallsBackToConfigWhenServiceNil(t *testing.T) {
	cfg := config.Config{BaseURL: "https://auth.klarsyn.net"}

	got := resolveMagicLinkBaseURL(cfg, nil)
	want := "https://auth.klarsyn.net"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolveMagicLinkBaseURL_DifferentServicesGetDifferentHosts(t *testing.T) {
	cfg := config.Config{BaseURL: "https://auth.klarsyn.net"}

	spekto := resolveMagicLinkBaseURL(cfg, &gen.Service{ID: "spekto", AuthHost: strPtr("auth.spekto.live")})
	vinkjeller := resolveMagicLinkBaseURL(cfg, &gen.Service{ID: "vinkjeller", AuthHost: strPtr("auth.lilleklo.work")})

	if spekto == vinkjeller {
		t.Errorf("spekto og vinkjeller skal få ulike baseURL, begge ble %q", spekto)
	}
	if spekto != "https://auth.spekto.live" {
		t.Errorf("spekto: got %q", spekto)
	}
	if vinkjeller != "https://auth.lilleklo.work" {
		t.Errorf("vinkjeller: got %q", vinkjeller)
	}
}
