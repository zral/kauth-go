package token_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

// payloadMap dekoder JWT-nyttelasten uten å verifisere, så testen ser
// nøyaktig hvilke claims som ligger i tokenet (ikke bare de Claims-strukten kjenner).
func payloadMap(t *testing.T, jwtStr string) map[string]any {
	t.Helper()
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		t.Fatalf("ikke et JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("dekode nyttelast: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse nyttelast: %v", err)
	}
	return m
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func idService() gen.Service {
	s := testService()
	s.SubFormat = "id"
	return s
}

func idUser() gen.User {
	u := testUser()
	u.PublicID = "0b6f3c1e-8d2a-4f6b-9a41-7c5e2d9b1a30"
	return u
}

// K8: claimsettet for sub_format=email er hentet fra koden på 46ec231 (F1,
// før F2) og hardkodet. nbf er med i det faktiske settet. Et nytt eller
// manglende claim er en kontraktsendring for klientene.
func TestClaims_SubFormatEmail_Unchanged(t *testing.T) {
	iss := newTestIssuer(t)
	wantAccess := []string{"aud", "email", "exp", "groups", "iat", "iss", "jti", "name", "nbf", "org", "sub", "token_use"}
	wantID := []string{"aud", "email", "exp", "groups", "iat", "iss", "jti", "name", "nbf", "nonce", "org", "sub", "token_use"}

	at, err := iss.IssueAccess(idUser(), testService()) // public_id satt, men tjenesten er email
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	pm := payloadMap(t, at)
	if got := sortedKeys(pm); !slices.Equal(got, wantAccess) {
		t.Errorf("access-claims: fikk %v, ville ha %v", got, wantAccess)
	}
	if pm["sub"] != "test@example.com" || pm["email"] != "test@example.com" {
		t.Errorf("sub skal være e-post: sub=%v email=%v", pm["sub"], pm["email"])
	}

	it, err := iss.IssueIDToken(idUser(), testService(), "n-1")
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	im := payloadMap(t, it)
	if got := sortedKeys(im); !slices.Equal(got, wantID) {
		t.Errorf("id-claims: fikk %v, ville ha %v", got, wantID)
	}
	if im["sub"] != "test@example.com" {
		t.Errorf("sub skal være e-post: %v", im["sub"])
	}
}

func TestClaims_SubFormatID(t *testing.T) {
	iss := newTestIssuer(t)
	u := idUser()

	at, err := iss.IssueAccess(u, idService())
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	it, err := iss.IssueIDToken(u, idService(), "n-1")
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	for name, tok := range map[string]string{"access": at, "id": it} {
		m := payloadMap(t, tok)
		if m["sub"] != u.PublicID {
			t.Errorf("%s: sub = %v, ville ha public_id", name, m["sub"])
		}
		if m["email"] != u.Email {
			t.Errorf("%s: email skal være med: %v", name, m["email"])
		}
	}

	// Admin-token er uendret: e-post som sub uansett public_id.
	adm, err := iss.IssueAdmin(u, 0)
	if err != nil {
		t.Fatalf("IssueAdmin: %v", err)
	}
	if sub := payloadMap(t, adm)["sub"]; sub != u.Email {
		t.Errorf("admin-sub skal være e-post: %v", sub)
	}
}

// En tom sub ville gjort alle brukere like for klienten.
func TestClaims_SubFormatID_MissingPublicIDFails(t *testing.T) {
	iss := newTestIssuer(t)
	if _, err := iss.IssueAccess(testUser(), idService()); err == nil {
		t.Fatal("forventet feil når public_id mangler")
	}
}

func TestNewPublicID_FormatAndUnique(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id, err := token.NewPublicID()
		if err != nil {
			t.Fatalf("NewPublicID: %v", err)
		}
		if !re.MatchString(id) {
			t.Fatalf("ugyldig format: %q", id)
		}
		if seen[id] {
			t.Fatalf("duplikat: %q", id)
		}
		seen[id] = true
	}
}

// PD13: barnet arver user_id fra forelderen, også gjennom flere rotasjoner.
func TestRotate_InheritsUserID(t *testing.T) {
	sqlDB := openTxDB(t)
	ctx := context.Background()
	svc := token.NewRefreshService(sqlDB, audit.NewNoop())

	plain, err := svc.Issue(ctx, testUser(), testService(), "ip", "ua")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	root := rowByPlain(t, sqlDB, plain)
	if root.UserID == nil || *root.UserID != testUser().ID {
		t.Fatalf("rot skal ha user_id %d, fikk %v", testUser().ID, root.UserID)
	}
	for n := 1; n <= 2; n++ {
		res, err := svc.Rotate(ctx, plain, "ip", "ua")
		if err != nil {
			t.Fatalf("Rotate %d: %v", n, err)
		}
		if res.UserID == nil || *res.UserID != testUser().ID {
			t.Fatalf("RotationResult.UserID gen %d: %v", n, res.UserID)
		}
		child := rowByPlain(t, sqlDB, res.NewToken)
		if child.UserID == nil || *child.UserID != testUser().ID {
			t.Fatalf("barn gen %d skal arve user_id: %v", n, child.UserID)
		}
		plain = res.NewToken
	}
}
