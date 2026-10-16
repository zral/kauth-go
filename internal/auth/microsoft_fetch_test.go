package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// msFetchServer er en lokal stand-in for Microsofts token- og JWKS-endepunkt.
// Ingen kall går mot Microsoft.
type msFetchServer struct {
	srv     *httptest.Server
	key     *rsa.PrivateKey
	idToken func() string // tom streng: svaret mangler id_token
	status  int
}

func newMSFetchServer(t *testing.T) *msFetchServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	s := &msFetchServer{key: key, status: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if s.status != http.StatusOK {
			http.Error(w, "boom", s.status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{"access_token": "a", "token_type": "Bearer"}
		if s.idToken != nil {
			if tok := s.idToken(); tok != "" {
				resp["id_token"] = tok
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		jwk := map[string]string{
			"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk}})
	})
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	// Global søm: tester som bruker newMSFetchServer, kan ikke bruke t.Parallel.
	old := msKeysURL
	msKeysURL = s.srv.URL + "/keys"
	t.Cleanup(func() { msKeysURL = old })
	return s
}

func (s *msFetchServer) sign(t *testing.T, key *rsa.PrivateKey, aud string, exp time.Time) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "https://login.microsoftonline.com/" + msOrgTid + "/v2.0", "aud": aud,
		"sub": "s", "exp": exp.Unix(), "iat": time.Now().Unix(),
		"tid": msOrgTid, "oid": "11111111-2222-3333-4444-555555555555", "email": "a@b.no",
	})
	tok.Header["kid"] = "k1"
	out, err := tok.SignedString(key)
	require.NoError(t, err)
	return out
}

func (s *msFetchServer) cfg() *oauth2.Config {
	return &oauth2.Config{ClientID: "client-1", ClientSecret: "x",
		Endpoint: oauth2.Endpoint{TokenURL: s.srv.URL + "/token", AuthStyle: oauth2.AuthStyleInParams}}
}

// D2 / AK3.3 / S31: feilene i fetchMSClaims får hver sin sentinel, så
// HandleCallback kan audite reason=code_exchange og reason=id_token.
func TestFetchMSClaims_Sentinels(t *testing.T) {
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	future, past := time.Now().Add(time.Hour), time.Now().Add(-time.Hour)

	cases := []struct {
		name    string
		status  int
		idToken func(s *msFetchServer, t *testing.T) string
		want    error
	}{
		{name: "token-endepunktet svarer 500", status: http.StatusInternalServerError, want: errMSCodeExchange},
		{name: "svar uten id_token", status: http.StatusOK, idToken: func(*msFetchServer, *testing.T) string { return "" }, want: errMSIDToken},
		{name: "feil aud", status: http.StatusOK, idToken: func(s *msFetchServer, t *testing.T) string { return s.sign(t, s.key, "annen-klient", future) }, want: errMSIDToken},
		{name: "utløpt", status: http.StatusOK, idToken: func(s *msFetchServer, t *testing.T) string { return s.sign(t, s.key, "client-1", past) }, want: errMSIDToken},
		{name: "feil signatur", status: http.StatusOK, idToken: func(s *msFetchServer, t *testing.T) string { return s.sign(t, other, "client-1", future) }, want: errMSIDToken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newMSFetchServer(t)
			s.status = tc.status
			if tc.idToken != nil {
				s.idToken = func() string { return tc.idToken(s, t) }
			}
			_, err := fetchMSClaims(context.Background(), s.cfg(), "code")
			require.ErrorIs(t, err, tc.want)
			if tc.want == errMSCodeExchange {
				require.NotErrorIs(t, err, errMSIDToken)
			} else {
				require.NotErrorIs(t, err, errMSCodeExchange)
			}
		})
	}

	t.Run("gyldig token gir claims", func(t *testing.T) {
		s := newMSFetchServer(t)
		s.idToken = func() string { return s.sign(t, s.key, "client-1", future) }
		cl, err := fetchMSClaims(context.Background(), s.cfg(), "code")
		require.NoError(t, err)
		require.Equal(t, msOrgTid, cl.Tid)
	})
}

// D2: feil i id_token-verifiseringen auditeres som reason=id_token uten e-post
// og tid; redirecten er uendret.
func TestMSCallback_IDTokenFailure_Audited(t *testing.T) {
	f, _ := newMSFixture(t, 0, nil)
	f.h.fetchClaims = func(context.Context, *oauth2.Config, string) (msClaims, error) {
		return msClaims{Tid: msOrgTid}, fmt.Errorf("%w: boom", errMSIDToken)
	}
	w := httptest.NewRecorder()
	f.h.HandleCallback(w, msStateCookieReq(t, f, "n"))

	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Equal(t, "/login?error=login_failed&service=klarsyn", w.Header().Get("Location"))
	requireRedirectBodyOnly(t, w)
	ev := lbOfType(drainAudit(t, f.q, f.h.aud), "microsoft_oidc_rejected")
	require.Len(t, ev, 1)
	require.NotNil(t, ev[0].Details)
	require.Equal(t, "reason=id_token", *ev[0].Details)
	require.Empty(t, ev[0].Email)
}
