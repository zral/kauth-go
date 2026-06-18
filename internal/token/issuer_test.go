package token_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

func newTestIssuer(t *testing.T) *token.Issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generere RSA-nøkkel: %v", err)
	}
	iss, err := token.NewIssuer(key, &key.PublicKey, "https://auth.example.com", 30*24*time.Hour, 1*time.Hour)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return iss
}

func testUser() gen.User {
	name := "Test Bruker"
	return gen.User{ID: 1, Email: "test@example.com", Name: &name, Roles: "bruker", Orgs: "testorg,annenorg"}
}

func testService() gen.Service {
	return gen.Service{ID: "testsvc", AccessTokenTtl: "P1D", JwtCookieName: "kauth_token"}
}

func TestIssueAccess_VerifyRoundtrip(t *testing.T) {
	iss := newTestIssuer(t)
	tok, err := iss.IssueAccess(testUser(), testService())
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	claims, err := iss.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Email != "test@example.com" {
		t.Errorf("feil email: %q", claims.Email)
	}
	if len(claims.Org) != 2 {
		t.Errorf("forventet 2 orger, fikk %d", len(claims.Org))
	}
	if claims.TokenUse != "access" {
		t.Errorf("forventet token_use=access, fikk %q", claims.TokenUse)
	}
}

func TestIssueAdmin_HasAdminTokenUse(t *testing.T) {
	iss := newTestIssuer(t)
	tok, err := iss.IssueAdmin(testUser(), 1*time.Hour)
	if err != nil {
		t.Fatalf("IssueAdmin: %v", err)
	}
	claims, err := iss.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.TokenUse != "admin" {
		t.Errorf("forventet token_use=admin, fikk %q", claims.TokenUse)
	}
}

func TestVerify_RejectsExpiredToken(t *testing.T) {
	iss := newTestIssuer(t)
	tok, err := iss.IssueWithTTL(testUser(), testService(), -1*time.Second)
	if err != nil {
		t.Fatalf("IssueWithTTL: %v", err)
	}
	_, err = iss.Verify(tok)
	if err == nil {
		t.Fatal("forventet feil for utløpt token, fikk nil")
	}
}

func TestJWKSHandler_ReturnsJSON(t *testing.T) {
	iss := newTestIssuer(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	iss.JWKSHandler(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("forventet 200, fikk %d", w.Code)
	}
	var jwks map[string]any
	if err := json.NewDecoder(w.Body).Decode(&jwks); err != nil {
		t.Fatalf("JWKS er ikke gyldig JSON: %v", err)
	}
	if _, ok := jwks["keys"]; !ok {
		t.Error("JWKS mangler 'keys'-felt")
	}
}
