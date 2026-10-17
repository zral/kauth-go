package token_test

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/zral/kauth-go/internal/token"
)

const ringIssuer = "https://auth.example.com"

func genKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pubOf(kid string, k *rsa.PrivateKey) *token.PublicKey {
	return &token.PublicKey{KID: kid, Public: &k.PublicKey}
}

func validClaims() token.Claims {
	now := time.Now()
	return token.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: ringIssuer, Subject: "a@example.com", Audience: jwt.ClaimStrings{"testsvc"},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)), IssuedAt: jwt.NewNumericDate(now),
		},
		Email: "a@example.com", TokenUse: "access",
	}
}

// signWith lager et token med valgfri kid-header (nil = ingen kid).
func signWith(t *testing.T, key *rsa.PrivateKey, kid any, claims token.Claims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if kid != nil {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func ringIssuerOf(t *testing.T, ring token.KeyRing) *token.Issuer {
	t.Helper()
	iss, err := token.NewIssuer(ring, ringIssuer, time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return iss
}

func TestKeyRing_Validate(t *testing.T) {
	cur, other, third := genKey(t), genKey(t), genKey(t)
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	base := func() token.KeyRing { return token.NewSingleKeyRing(cur) }
	cases := []struct {
		name string
		mod  func(r *token.KeyRing)
		ok   bool
	}{
		{"kun current", func(r *token.KeyRing) {}, true},
		{"alle tre", func(r *token.KeyRing) { r.Next = pubOf("n", other); r.Previous = pubOf("p", third) }, true},
		{"ugyldig current-kid", func(r *token.KeyRing) { r.Current.KID = "ø" }, false},
		{"tom current-kid", func(r *token.KeyRing) { r.Current.KID = "" }, false},
		{"for lang kid", func(r *token.KeyRing) { r.Current.KID = strings.Repeat("a", 65) }, false},
		{"ugyldig next-kid", func(r *token.KeyRing) { r.Next = pubOf("a b", other) }, false},
		{"next-kid lik current", func(r *token.KeyRing) { r.Next = pubOf("kauth-1", other) }, false},
		{"previous-kid lik next", func(r *token.KeyRing) { r.Next = pubOf("x", other); r.Previous = pubOf("x", third) }, false},
		{"svak next", func(r *token.KeyRing) { r.Next = pubOf("n", weak) }, false},
		{"svak previous", func(r *token.KeyRing) { r.Previous = pubOf("p", weak) }, false},
		{"offentlig current tilhører ikke privat", func(r *token.KeyRing) { r.Current.Public = &other.PublicKey }, false},
		{"mangler privat", func(r *token.KeyRing) { r.Current.Private = nil }, false},
		{"next uten offentlig nøkkel", func(r *token.KeyRing) { r.Next = &token.PublicKey{KID: "n"} }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := base()
			tc.mod(&r)
			_, err := token.NewIssuer(r, ringIssuer, time.Hour, time.Hour)
			if (err == nil) != tc.ok {
				t.Errorf("err = %v, ok forventet %v", err, tc.ok)
			}
		})
	}
	// Svak current (E-ulikhet fanges via sammenligning av N og E).
	r := base()
	r.Current.Public = &rsa.PublicKey{N: cur.N, E: 3}
	if _, err := token.NewIssuer(r, ringIssuer, time.Hour, time.Hour); err == nil {
		t.Error("avvik i E skulle avvises")
	}
}

func TestJWKS_KeyCountAndOrder(t *testing.T) {
	cur, next, prev := genKey(t), genKey(t), genKey(t)
	cases := []struct {
		name string
		mod  func(r *token.KeyRing)
		kids []string
	}{
		{"1 nøkkel", func(r *token.KeyRing) {}, []string{"c"}},
		{"current og next", func(r *token.KeyRing) { r.Next = pubOf("n", next) }, []string{"c", "n"}},
		{"current og previous", func(r *token.KeyRing) { r.Previous = pubOf("p", prev) }, []string{"c", "p"}},
		{"3 nøkler", func(r *token.KeyRing) { r.Next = pubOf("n", next); r.Previous = pubOf("p", prev) }, []string{"c", "n", "p"}},
	}
	mods := map[string]*rsa.PrivateKey{"c": cur, "n": next, "p": prev}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ring := token.NewSingleKeyRing(cur)
			ring.Current.KID = "c"
			tc.mod(&ring)
			iss := ringIssuerOf(t, ring)
			rec := httptest.NewRecorder()
			iss.JWKSHandler(rec, httptest.NewRequest("GET", "/.well-known/jwks.json", nil))
			if got := rec.Header().Get("Cache-Control"); got != "public, max-age=3600" {
				t.Errorf("Cache-Control = %q", got)
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q", got)
			}
			var set struct {
				Keys []map[string]string `json:"keys"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
				t.Fatal(err)
			}
			if len(set.Keys) != len(tc.kids) {
				t.Fatalf("antall nøkler = %d, forventet %d", len(set.Keys), len(tc.kids))
			}
			for j, kid := range tc.kids {
				k := set.Keys[j]
				if k["kid"] != kid || k["kty"] != "RSA" || k["use"] != "sig" || k["alg"] != "RS256" {
					t.Errorf("nøkkel %d: %v", j, k)
				}
				want := mods[kid]
				if k["n"] != base64.RawURLEncoding.EncodeToString(want.N.Bytes()) ||
					k["e"] != base64.RawURLEncoding.EncodeToString(big.NewInt(int64(want.E)).Bytes()) {
					t.Errorf("nøkkel %d (%s) har feil n/e", j, kid)
				}
			}
		})
	}
}

func TestVerify_KeyRingMatrix(t *testing.T) {
	cur, next, prev, stranger := genKey(t), genKey(t), genKey(t), genKey(t)
	ring := token.NewSingleKeyRing(cur)
	ring.Next = pubOf("kauth-2", next)
	ring.Previous = pubOf("kauth-0", prev)
	iss := ringIssuerOf(t, ring)
	c := validClaims()

	expired := validClaims()
	expired.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
	wrongIss := validClaims()
	wrongIss.Issuer = "https://evil.example.com"

	cases := []struct {
		name string
		tok  string
		ok   bool
	}{
		{"current med kid", signWith(t, cur, "kauth-1", c), true},
		{"current uten kid", signWith(t, cur, nil, c), true},
		{"previous med kid", signWith(t, prev, "kauth-0", c), true},
		{"previous uten kid", signWith(t, prev, nil, c), true},
		{"next-kid med next-nøkkel", signWith(t, next, "kauth-2", c), false},
		{"next-kid med current-nøkkel", signWith(t, cur, "kauth-2", c), false},
		{"next uten kid", signWith(t, next, nil, c), false},
		{"ukjent kid", signWith(t, cur, "ukjent", c), false},
		{"tom kid", signWith(t, cur, "", c), false},
		{"current-kid men previous-nøkkel", signWith(t, prev, "kauth-1", c), false},
		{"previous-kid men current-nøkkel", signWith(t, cur, "kauth-0", c), false},
		{"current-kid med fremmed nøkkel", signWith(t, stranger, "kauth-1", c), false},
		{"uten kid, fremmed nøkkel", signWith(t, stranger, nil, c), false},
		{"kid som tall", signWith(t, cur, 1, c), false},
		{"kid som liste", signWith(t, cur, []string{"kauth-1"}, c), false},
		{"previous uten kid, utløpt", signWith(t, prev, nil, expired), false},
		{"previous med kid, feil issuer", signWith(t, prev, "kauth-0", wrongIss), false},
		{"previous uten kid, feil issuer", signWith(t, prev, nil, wrongIss), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := iss.Verify(tc.tok, token.ExpectAccess)
			if (err == nil) != tc.ok {
				t.Errorf("err = %v, ok forventet %v", err, tc.ok)
			}
		})
	}
}

func TestVerify_RejectsOtherAlgorithmsWithKeyRing(t *testing.T) {
	cur, prev := genKey(t), genKey(t)
	ring := token.NewSingleKeyRing(cur)
	ring.Previous = pubOf("kauth-0", prev)
	iss := ringIssuerOf(t, ring)
	c := validClaims()
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}

	none := enc(map[string]any{"alg": "none", "typ": "JWT", "kid": "kauth-1"}) + "." + enc(c) + "."
	hsInput := enc(map[string]any{"alg": "HS256", "typ": "JWT", "kid": "kauth-1"}) + "." + enc(c)
	mac := hmac.New(sha256.New, []byte("hemmelig"))
	mac.Write([]byte(hsInput))
	hs256 := hsInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	rs512, err := jwt.NewWithClaims(jwt.SigningMethodRS512, c).SignedString(cur)
	if err != nil {
		t.Fatal(err)
	}
	rs512kid := jwt.NewWithClaims(jwt.SigningMethodRS512, c)
	rs512kid.Header["kid"] = "kauth-1"
	rs512k, err := rs512kid.SignedString(cur)
	if err != nil {
		t.Fatal(err)
	}
	for name, tok := range map[string]string{"none": none, "HS256": hs256, "RS512 uten kid": rs512, "RS512 med kid": rs512k} {
		if _, err := iss.Verify(tok, token.ExpectAccess); err == nil {
			t.Errorf("%s ble godtatt", name)
		}
	}
}

func TestSign_OnlyCurrentSigns(t *testing.T) {
	cur, next, prev := genKey(t), genKey(t), genKey(t)
	ring := token.NewSingleKeyRing(cur)
	ring.Current.KID = "kauth-7"
	ring.Next = pubOf("kauth-8", next)
	ring.Previous = pubOf("kauth-6", prev)
	iss := ringIssuerOf(t, ring)

	tok, err := iss.IssueAccess(testUser(), testService())
	if err != nil {
		t.Fatal(err)
	}
	if kid := headerOf(t, tok)["kid"]; kid != "kauth-7" {
		t.Errorf("kid = %v, forventet kauth-7", kid)
	}
	// Signaturen skal stemme med current og ingen av de andre.
	parts := strings.Split(tok, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	for name, k := range map[string]*rsa.PublicKey{"next": &next.PublicKey, "previous": &prev.PublicKey} {
		if jwt.SigningMethodRS256.Verify(parts[0]+"."+parts[1], sig, k) == nil {
			t.Errorf("tokenet er signert med %s", name)
		}
	}
	if err := jwt.SigningMethodRS256.Verify(parts[0]+"."+parts[1], sig, &cur.PublicKey); err != nil {
		t.Errorf("tokenet er ikke signert med current: %v", err)
	}
}

// Fallback til previous gjelder bare signaturfeil. Et utløpt token signert med
// current uten kid skal feile på utløp, ikke prøves på nytt mot previous og
// komme tilbake som signaturfeil.
func TestVerify_NoFallbackOnNonSignatureErrors(t *testing.T) {
	cur, prev := genKey(t), genKey(t)
	ring := token.NewSingleKeyRing(cur)
	ring.Previous = pubOf("kauth-0", prev)
	iss := ringIssuerOf(t, ring)

	expired := validClaims()
	expired.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
	_, err := iss.Verify(signWith(t, cur, nil, expired), token.ExpectAccess)
	if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Errorf("utløpt current-token uten kid: err = %v, forventet ErrTokenExpired", err)
	}

	wrongIss := validClaims()
	wrongIss.Issuer = "https://evil.example.com"
	_, err = iss.Verify(signWith(t, cur, nil, wrongIss), token.ExpectAccess)
	if !errors.Is(err, jwt.ErrTokenInvalidIssuer) {
		t.Errorf("feil issuer uten kid: err = %v, forventet ErrTokenInvalidIssuer", err)
	}
}

func TestVerify_RejectsPSAndHMACWithPublicKeyAsSecret(t *testing.T) {
	cur := genKey(t)
	iss := ringIssuerOf(t, token.NewSingleKeyRing(cur))
	c := validClaims()

	ps := jwt.NewWithClaims(jwt.SigningMethodPS256, c)
	ps.Header["kid"] = "kauth-1"
	psTok, err := ps.SignedString(cur)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.MarshalPKIXPublicKey(&cur.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	hs := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	hs.Header["kid"] = "kauth-1"
	hsTok, err := hs.SignedString(pemPub)
	if err != nil {
		t.Fatal(err)
	}
	for name, tok := range map[string]string{"PS256": psTok, "HS256 med offentlig PEM som hemmelighet": hsTok} {
		if _, err := iss.Verify(tok, token.ExpectAccess); err == nil {
			t.Errorf("%s ble godtatt", name)
		}
	}
}
