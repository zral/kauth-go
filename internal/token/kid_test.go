package token_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/zral/kauth-go/internal/token"
)

func newKeyedIssuer(t *testing.T) (*token.Issuer, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generere RSA-nøkkel: %v", err)
	}
	iss, err := token.NewIssuer(key, &key.PublicKey, "https://auth.example.com", time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return iss, key
}

func headerOf(t *testing.T, tok string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	if err != nil {
		t.Fatalf("dekode header: %v", err)
	}
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatalf("parse header: %v", err)
	}
	return h
}

func TestSign_AllTokenTypesCarryKid(t *testing.T) {
	iss := newTestIssuer(t)
	access, err := iss.IssueAccess(testUser(), testService())
	if err != nil {
		t.Fatal(err)
	}
	admin, err := iss.IssueAdmin(testUser(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	id, err := iss.IssueIDToken(testUser(), testService(), "n")
	if err != nil {
		t.Fatal(err)
	}
	for name, tok := range map[string]string{"access": access, "admin": admin, "id": id} {
		h := headerOf(t, tok)
		if h["kid"] != "kauth-1" {
			t.Errorf("%s: kid = %v, forventet kauth-1", name, h["kid"])
		}
		if h["alg"] != "RS256" {
			t.Errorf("%s: alg = %v", name, h["alg"])
		}
	}
}

func TestVerify_AcceptsTokenWithAndWithoutKid(t *testing.T) {
	iss, key := newKeyedIssuer(t)
	svc := testService()

	withKid, err := iss.IssueAccess(testUser(), svc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.Verify(withKid, token.ExpectAccess); err != nil {
		t.Errorf("token med kid avvist: %v", err)
	}

	// Gammelt token: samme claims, signert uten kid i headeren.
	claims := &token.Claims{}
	if _, _, err := jwt.NewParser().ParseUnverified(withKid, claims); err != nil {
		t.Fatal(err)
	}
	old := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	noKid, err := old.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := headerOf(t, noKid)["kid"]; ok {
		t.Fatal("testtokenet skulle ikke ha kid")
	}
	if _, err := iss.Verify(noKid, token.ExpectAccess); err != nil {
		t.Errorf("token uten kid avvist: %v", err)
	}
}

func TestJWKS_Unchanged(t *testing.T) {
	iss, key := newKeyedIssuer(t)
	rec := httptest.NewRecorder()
	iss.JWKSHandler(rec, httptest.NewRequest("GET", "/.well-known/jwks.json", nil))
	want := fmt.Sprintf(`{"keys":[{"alg":"RS256","e":%q,"kid":"kauth-1","kty":"RSA","n":%q,"use":"sig"}]}`,
		base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		base64.RawURLEncoding.EncodeToString(key.N.Bytes()))
	if got := strings.TrimSpace(rec.Body.String()); got != want {
		t.Errorf("JWKS endret:\ngot  %s\nwant %s", got, want)
	}
}

// clientVerify etterligner en typisk klient: finn nøkkel i JWKS etter kid,
// ellers keys[0], og verifiser RS256.
func clientVerify(t *testing.T, iss *token.Issuer, tok string) error {
	t.Helper()
	rec := httptest.NewRecorder()
	iss.JWKSHandler(rec, httptest.NewRequest("GET", "/.well-known/jwks.json", nil))
	var set struct {
		Keys []struct{ Kid, N, E string } `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}
	_, err := jwt.Parse(tok, func(tk *jwt.Token) (any, error) {
		k := &set.Keys[0]
		if kid, _ := tk.Header["kid"].(string); kid != "" {
			for j := range set.Keys {
				if set.Keys[j].Kid == kid {
					k = &set.Keys[j]
				}
			}
		}
		n, _ := base64.RawURLEncoding.DecodeString(k.N)
		e, _ := base64.RawURLEncoding.DecodeString(k.E)
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	return err
}

func TestClientStyleVerification_OldAndNewTokens(t *testing.T) {
	iss, key := newKeyedIssuer(t)
	newTok, err := iss.IssueAccess(testUser(), testService())
	if err != nil {
		t.Fatal(err)
	}
	claims := &token.Claims{}
	if _, _, err := jwt.NewParser().ParseUnverified(newTok, claims); err != nil {
		t.Fatal(err)
	}
	oldTok, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, tok := range map[string]string{"ny": newTok, "gammel": oldTok} {
		if err := clientVerify(t, iss, tok); err != nil {
			t.Errorf("%s token: %v", name, err)
		}
	}
}
