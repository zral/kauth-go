package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/zral/kauth-go/internal/token"
)

// Grensene testes med injisert klokke. Mot ekte klokke kan ingen test treffe
// nøyaktig 120 s, så `<=` mot `<` og 120 mot 121 ville passert ubemerket.
func TestTokenAge_Boundaries(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		offset time.Duration // iat = now - offset
		fresh  bool
	}{
		{"nøyaktig maks alder", dispatchMaxTokenAge, true},
		{"ett sekund over maks", dispatchMaxTokenAge + time.Second, false},
		{"nøyaktig maks klokkeavvik", -dispatchClockSkew, true},
		{"ett sekund forbi klokkeavvik", -dispatchClockSkew - time.Second, false},
		{"nyutstedt", 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			claims := &token.Claims{RegisteredClaims: jwt.RegisteredClaims{IssuedAt: jwt.NewNumericDate(now.Add(-c.offset))}}
			if _, ok := tokenAge(claims, now); ok != c.fresh {
				t.Fatalf("tokenAge(iat=now-%v) fersk=%v, forventet %v", c.offset, ok, c.fresh)
			}
		})
	}
	if dispatchMaxTokenAge != 120*time.Second || dispatchClockSkew != 30*time.Second {
		t.Fatalf("grensene er endret: maks=%v avvik=%v (PD4 i 010)", dispatchMaxTokenAge, dispatchClockSkew)
	}
	if _, ok := tokenAge(&token.Claims{}, now); ok {
		t.Fatal("token uten iat skal ikke regnes som ferskt")
	}
}
