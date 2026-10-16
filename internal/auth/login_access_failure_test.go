package auth

import (
	"context"
	"crypto/rsa"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/token"
)

// brokenIssuer signerer med en 12-bits nøkkel, som crypto/rsa avviser. Da
// feiler IssueAccess uten at produksjonskode må endres.
func brokenIssuer(t *testing.T) *token.Issuer {
	t.Helper()
	k := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: big.NewInt(3233), E: 17}, D: big.NewInt(2753)}
	iss, err := token.NewIssuer(k, &k.PublicKey, "https://test.example.com", time.Minute, time.Minute)
	require.NoError(t, err)
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

			if m.name == "google" {
				require.Equal(t, http.StatusInternalServerError, w.Code)
				require.Equal(t, "kunne ikke utstede token\n", w.Body.String())
			} else {
				m.issueFailed(t, w, "klarsyn")
			}
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
