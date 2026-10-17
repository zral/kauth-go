package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

// brokenIssuer består ringvalideringen med en ekte 2048-bits nøkkel, men får
// ødelagt privatdelen etterpå. Da feiler IssueAccess uten at produksjonskode
// må endres, og uten å svekke valideringen i NewIssuer.
func brokenIssuer(t *testing.T) *token.Issuer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	iss, err := token.NewIssuer(token.NewSingleKeyRing(k), "https://test.example.com", time.Minute, time.Minute)
	require.NoError(t, err)
	k.D = nil
	k.Primes = nil
	k.Precomputed = rsa.PrecomputedValues{}
	_, err = iss.IssueAccess(gen.User{Email: "a@example.com"}, gen.Service{ID: "x", AccessTokenTtl: "PT1M"})
	require.Error(t, err, "nøkkelen skal være ubrukelig til signering")
	return iss
}

// Feil i access-token-utstedelsen (før refresh) skal gi samme svar som en
// utstedelsesfeil, ikke et policyavslag, for alle fire metodene: ingen
// refresh-cookie, ingen suksess-audit, ingen avslagsrad og ingen last_login.
func TestLoginBaseline_AccessTokenIssueFailure(t *testing.T) {
	for _, m := range lbMethods() {
		t.Run(m.name, func(t *testing.T) {
			e := newLBEnv(t)
			e.issuer = brokenIssuer(t)
			e.addService(t, "klarsyn", nil)
			user := e.addUser(t, "bruker@example.com", "user", "lars")
			svc := e.service(t, "klarsyn")

			w := m.login(t, e, svc, user)

			m.issueFailed(t, w, "klarsyn")
			require.Empty(t, w.Result().Cookies())
			require.NotContains(t, w.Header().Get("Location"), "/dispatch")
			require.NotContains(t, w.Body.String(), "rt=")

			got, err := e.q.GetUserByEmail(context.Background(), "bruker@example.com")
			require.NoError(t, err)
			require.Nil(t, got.LastLogin)
			events := e.events(t)
			require.Empty(t, lbOfType(events, m.auditType))
			lbNoRejections(t, events)
		})
	}
}
