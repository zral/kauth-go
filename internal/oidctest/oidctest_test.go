package oidctest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
)

const (
	cid         = "client-1"
	redirectURI = "http://127.0.0.1:1/cb"
	verifier    = "verifier-verifier-verifier-verifier-1234567"
)

func challenge(v string) string {
	s := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(s[:])
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func authorize(t *testing.T, p *IdP) url.Values {
	t.Helper()
	q := url.Values{
		"response_type": {"code"}, "client_id": {cid}, "redirect_uri": {redirectURI},
		"state": {"st"}, "nonce": {"no"}, "code_challenge": {challenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	resp, err := noRedirect.Get(p.URL() + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if !strings.HasPrefix(loc.String(), redirectURI) {
		t.Fatalf("redirect til %s", loc)
	}
	return loc.Query()
}

func tokenForm(code string) url.Values {
	return url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier},
	}
}

func postToken(t *testing.T, p *IdP, f url.Values, basic [2]string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("POST", p.URL()+"/token", strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic[0] != "" {
		req.SetBasicAuth(basic[0], basic[1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func payload(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("ikke en JWT: %q", tok)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	return m
}

func header(t *testing.T, tok string) map[string]any {
	b, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	var m map[string]any
	json.Unmarshal(b, &m)
	return m
}

func flow(t *testing.T, p *IdP, c Claims, m Mode, basic [2]string) map[string]any {
	t.Helper()
	p.Next(c, m)
	q := authorize(t, p)
	f := tokenForm(q.Get("code"))
	if basic[0] == "" {
		f.Set("client_id", cid)
	}
	st, body := postToken(t, p, f, basic)
	if st != 200 {
		t.Fatalf("token status %d %v", st, body)
	}
	return body
}

func TestHappyPathConfidential(t *testing.T) {
	p := New(t, Options{ClientID: cid, ClientSecret: "sec"})
	body := flow(t, p, Claims{Sub: "u1", Email: "u@x.no", Name: "U"}, ModeOK, [2]string{cid, "sec"})
	cl := payload(t, body["id_token"].(string))
	if cl["iss"] != p.Issuer() || cl["aud"] != cid || cl["sub"] != "u1" || cl["nonce"] != "no" ||
		cl["email"] != "u@x.no" || cl["email_verified"] != true {
		t.Fatalf("claims: %v", cl)
	}
	if header(t, body["id_token"].(string))["kid"] == "" {
		t.Fatal("kid mangler")
	}
	if p.Issuer() != p.URL() {
		t.Fatal("issuer skal være URL uten override")
	}
}

func TestCodeSingleUse(t *testing.T) {
	p := New(t, Options{ClientID: cid})
	q := authorize(t, p)
	f := url.Values{"client_id": {cid}}
	for k, v := range tokenForm(q.Get("code")) {
		f[k] = v
	}
	if st, _ := postToken(t, p, f, [2]string{}); st != 200 {
		t.Fatalf("første bruk: %d", st)
	}
	if st, _ := postToken(t, p, f, [2]string{}); st != 400 {
		t.Fatalf("gjenbruk skal gi 400, fikk %d", st)
	}
}

func TestTokenValidation(t *testing.T) {
	p := New(t, Options{ClientID: cid, ClientSecret: "sec"})
	good := [2]string{cid, "sec"}
	cases := []struct {
		name   string
		mut    func(url.Values)
		basic  [2]string
		status int
	}{
		{"feil redirect_uri", func(f url.Values) { f.Set("redirect_uri", "http://evil/") }, good, 400},
		{"feil verifier", func(f url.Values) { f.Set("code_verifier", "annet-annet-annet-annet-annet-annet-1234") }, good, 400},
		{"uten verifier", func(f url.Values) { f.Del("code_verifier") }, good, 400},
		{"feil hemmelighet", func(url.Values) {}, [2]string{cid, "nei"}, 401},
		{"uten klientautentisering", func(url.Values) {}, [2]string{}, 401},
		{"feil grant_type", func(f url.Values) { f.Set("grant_type", "password") }, good, 400},
		{"ukjent kode", func(f url.Values) { f.Set("code", "nope") }, good, 400},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q := authorize(t, p)
			f := tokenForm(q.Get("code"))
			c.mut(f)
			if st, _ := postToken(t, p, f, c.basic); st != c.status {
				t.Fatalf("status %d, ventet %d", st, c.status)
			}
		})
	}
}

func TestClientSecretPostAndRequestsLog(t *testing.T) {
	p := New(t, Options{ClientID: cid, ClientSecret: "sec"})
	q := authorize(t, p)
	f := tokenForm(q.Get("code"))
	f.Set("client_id", cid)
	f.Set("client_secret", "sec")
	if st, _ := postToken(t, p, f, [2]string{}); st != 200 {
		t.Fatalf("post-auth: %d", st)
	}
	var tokReq *Request
	for _, r := range p.Requests() {
		if r.Path == "/token" {
			r := r
			tokReq = &r
		}
	}
	if tokReq == nil || !tokReq.PKCEValid || tokReq.ClientAuth != "post" {
		t.Fatalf("token-logg: %+v", tokReq)
	}
	if _, ok := tokReq.Query["code_verifier"]; ok {
		t.Fatal("code_verifier skal ikke loggføres")
	}
	if _, ok := tokReq.Query["client_secret"]; ok {
		t.Fatal("client_secret skal ikke loggføres")
	}
	p.Reset()
	if len(p.Requests()) != 0 {
		t.Fatal("Reset tømmer loggen")
	}
}

func TestBadPKCELogged(t *testing.T) {
	p := New(t, Options{ClientID: cid})
	q := authorize(t, p)
	f := tokenForm(q.Get("code"))
	f.Set("client_id", cid)
	f.Set("code_verifier", "feil-feil-feil-feil-feil-feil-feil-feil-1")
	postToken(t, p, f, [2]string{})
	rs := p.Requests()
	if last := rs[len(rs)-1]; last.Path != "/token" || last.PKCEValid {
		t.Fatalf("%+v", last)
	}
}

func TestAuthorizeRequiresPKCEAndClient(t *testing.T) {
	p := New(t, Options{ClientID: cid})
	for _, q := range []url.Values{
		{"response_type": {"code"}, "client_id": {"annen"}, "redirect_uri": {redirectURI}, "code_challenge": {"x"}, "code_challenge_method": {"S256"}},
		{"response_type": {"code"}, "client_id": {cid}, "redirect_uri": {redirectURI}},
		{"response_type": {"code"}, "client_id": {cid}, "redirect_uri": {redirectURI}, "code_challenge": {"x"}, "code_challenge_method": {"plain"}},
	} {
		resp, _ := noRedirect.Get(p.URL() + "/authorize?" + q.Encode())
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatalf("ventet 400, fikk %d for %v", resp.StatusCode, q)
		}
	}
}

func TestModesChangeIDToken(t *testing.T) {
	const secret = "sec-0123456789-0123456789-0123456789"
	p := New(t, Options{ClientID: cid, ClientSecret: secret})
	basic := [2]string{cid, secret}
	get := func(m Mode) string {
		return flow(t, p, Claims{Sub: "u"}, m, basic)["id_token"].(string)
	}
	if cl := payload(t, get(ModeWrongIss)); cl["iss"] == p.Issuer() {
		t.Error("wrong_iss")
	}
	if cl := payload(t, get(ModeWrongAud)); cl["aud"] == cid {
		t.Error("wrong_aud")
	}
	cl := payload(t, get(ModeMultiAudBadAzp))
	if aud, ok := cl["aud"].([]any); !ok || len(aud) != 2 || cl["azp"] == cid {
		t.Errorf("multi_aud_bad_azp: %v", cl)
	}
	if cl := payload(t, get(ModeWrongNonce)); cl["nonce"] == "no" {
		t.Error("wrong_nonce")
	}
	if cl := payload(t, get(ModeExpired)); int64(cl["exp"].(float64)) > time.Now().Unix() {
		t.Error("expired")
	}
	tok := get(ModeAlgNone)
	if header(t, tok)["alg"] != "none" || !strings.HasSuffix(tok, ".") {
		t.Errorf("alg_none: %s", tok)
	}
	if h := header(t, get(ModeAlgHS256)); h["alg"] != "HS256" {
		t.Errorf("alg_hs256: %v", h)
	}
	if h := header(t, get(ModeUnknownKid)); h["kid"] != "unknown-kid" {
		t.Errorf("unknown_kid: %v", h)
	}
	body := flow(t, p, Claims{Sub: "u"}, ModeNoIDToken, basic)
	if _, ok := body["id_token"]; ok {
		t.Error("no_id_token")
	}
	// Neste innlogging uten Next er ok igjen.
	if cl := payload(t, get(ModeOK)); cl["iss"] != p.Issuer() {
		t.Error("ok etter feilmodus")
	}
}

func TestHS256UsesModulusForPublicClient(t *testing.T) {
	p := New(t, Options{ClientID: cid})
	p.Next(Claims{Sub: "u"}, ModeAlgHS256)
	q := authorize(t, p)
	f := tokenForm(q.Get("code"))
	f.Set("client_id", cid)
	st, body := postToken(t, p, f, [2]string{})
	if st != 200 || header(t, body["id_token"].(string))["alg"] != "HS256" {
		t.Fatalf("%d %v", st, body)
	}
}

func TestEmailVerifiedVariants(t *testing.T) {
	p := New(t, Options{ClientID: cid})
	cases := []struct {
		ev   EmailVerified
		want any
		has  bool
	}{
		{EVTrue, true, true}, {EVFalse, false, true},
		{EVStringFalse, "false", true}, {EVStringTrue, "true", true}, {EVOmit, nil, false},
	}
	for _, c := range cases {
		p.Next(Claims{Sub: "u", Email: "a@b.no", EmailVerified: c.ev}, ModeOK)
		q := authorize(t, p)
		f := tokenForm(q.Get("code"))
		f.Set("client_id", cid)
		_, body := postToken(t, p, f, [2]string{})
		v, has := payload(t, body["id_token"].(string))["email_verified"]
		if has != c.has || v != c.want {
			t.Errorf("%d: %v %v", c.ev, v, has)
		}
	}
	var cl Claims
	json.Unmarshal([]byte(`{"sub":"a","email_verified":"false"}`), &cl)
	if cl.EmailVerified != EVStringFalse {
		t.Error("JSON streng")
	}
	json.Unmarshal([]byte(`{"sub":"a","email_verified":null}`), &cl)
	if cl.EmailVerified != EVOmit {
		t.Error("JSON null")
	}
	json.Unmarshal([]byte(`{"sub":"a","email_verified":false}`), &cl)
	if cl.EmailVerified != EVFalse {
		t.Error("JSON false")
	}
}

func TestAuthorizeErrorAndIssParam(t *testing.T) {
	p := New(t, Options{ClientID: cid, IssParam: true})
	p.Next(Claims{}, ModeAuthorizeError)
	q := authorize(t, p)
	if q.Get("error") != "access_denied" || q.Get("code") != "" || q.Get("state") != "st" || q.Get("iss") != p.Issuer() {
		t.Fatalf("%v", q)
	}
	if q.Get("error_description") == "" {
		t.Fatal("error_description skal finnes så ekko kan testes")
	}
	p.Next(Claims{}, ModeIssParamWrong)
	q = authorize(t, p)
	if q.Get("code") == "" || q.Get("iss") == p.Issuer() || q.Get("iss") == "" {
		t.Fatalf("%v", q)
	}
	p.Next(Claims{}, ModeOK)
	if q = authorize(t, p); q.Get("iss") != p.Issuer() {
		t.Fatalf("iss-param: %v", q)
	}
	p2 := New(t, Options{ClientID: cid})
	if q = authorize(t, p2); q.Has("iss") {
		t.Fatal("iss skal ikke sendes uten IssParam")
	}
}

func TestToken500AndSlow(t *testing.T) {
	p := New(t, Options{ClientID: cid, SlowDelay: 300 * time.Millisecond})
	f := func(code string) url.Values {
		v := tokenForm(code)
		v.Set("client_id", cid)
		return v
	}
	p.Next(Claims{Sub: "u"}, ModeToken500)
	if st, _ := postToken(t, p, f(authorize(t, p).Get("code")), [2]string{}); st != 500 {
		t.Fatalf("token_500: %d", st)
	}
	p.Next(Claims{Sub: "u"}, ModeTokenSlow)
	code := authorize(t, p).Get("code")
	start := time.Now()
	if st, _ := postToken(t, p, f(code), [2]string{}); st != 200 || time.Since(start) < 250*time.Millisecond {
		t.Fatalf("token_slow: %d etter %v", st, time.Since(start))
	}
}

func TestRotateKeyChangesJWKS(t *testing.T) {
	p := New(t, Options{ClientID: cid})
	kids := func() string {
		resp, err := http.Get(p.URL() + "/jwks")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var set struct {
			Keys []struct{ Kid, Kty string } `json:"keys"`
		}
		json.NewDecoder(resp.Body).Decode(&set)
		var out []string
		for _, k := range set.Keys {
			out = append(out, k.Kty+":"+k.Kid)
		}
		return strings.Join(out, ",")
	}
	before := kids()
	if !strings.Contains(before, "RSA:") || !strings.Contains(before, "EC:") {
		t.Fatalf("ventet RSA og EC: %s", before)
	}
	flow(t, p, Claims{Sub: "u"}, ModeRotateKey, [2]string{})
	if after := kids(); after == before {
		t.Fatal("rotate_key skal bytte kid")
	}
	if p.JWKSCount() != 2 {
		t.Fatalf("jwks-teller %d", p.JWKSCount())
	}
}

func discover(t *testing.T, p *IdP) (int, map[string]any) {
	t.Helper()
	c := &http.Client{Timeout: 5 * time.Second, CheckRedirect: noRedirect.CheckRedirect}
	resp, err := c.Get(p.URL() + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func TestDiscoveryModes(t *testing.T) {
	st, doc := discover(t, New(t, Options{ClientID: cid, ClientSecret: "s"}))
	if st != 200 || doc["jwks_uri"] == nil || doc["code_challenge_methods_supported"].([]any)[0] != "S256" ||
		doc["response_types_supported"].([]any)[0] != "code" {
		t.Fatalf("ok: %v", doc)
	}
	if m := doc["token_endpoint_auth_methods_supported"].([]any); len(m) != 2 {
		t.Fatalf("auth-metoder: %v", m)
	}
	pub := New(t, Options{ClientID: cid})
	if _, d := discover(t, pub); d["token_endpoint_auth_methods_supported"].([]any)[0] != "none" {
		t.Fatal("offentlig klient annonserer none")
	}

	p := New(t, Options{ClientID: cid, DiscoveryMode: DiscWrongIss})
	if _, d := discover(t, p); d["issuer"] == p.Issuer() {
		t.Error("wrong_issuer")
	}
	p = New(t, Options{ClientID: cid, DiscoveryMode: DiscHTTPEndpoint})
	if _, d := discover(t, p); !strings.HasPrefix(d["token_endpoint"].(string), "http://idp.example.net") {
		t.Error("http_endpoint")
	}
	p = New(t, Options{ClientID: cid, DiscoveryMode: DiscForeignJWKSHost})
	if _, d := discover(t, p); !strings.Contains(d["jwks_uri"].(string), "10.0.0.1") {
		t.Error("foreign_jwks_host")
	}
	p = New(t, Options{ClientID: cid, DiscoveryMode: DiscDown500})
	if st, _ := discover(t, p); st != 500 {
		t.Error("down500")
	}
	p = New(t, Options{ClientID: cid, DiscoveryMode: DiscRedirect})
	if st, _ := discover(t, p); st != 302 {
		t.Error("redirect")
	}
	p = New(t, Options{ClientID: cid, DiscoveryMode: DiscHuge})
	resp, _ := http.Get(p.URL() + "/.well-known/openid-configuration")
	n := 0
	buf := make([]byte, 32<<10)
	for {
		k, err := resp.Body.Read(buf)
		n += k
		if err != nil {
			break
		}
	}
	resp.Body.Close()
	if n <= 1<<20 {
		t.Errorf("huge: %d byte", n)
	}
	p = New(t, Options{ClientID: cid, DiscoveryMode: DiscSlow, SlowDelay: 200 * time.Millisecond})
	start := time.Now()
	discover(t, p)
	if time.Since(start) < 150*time.Millisecond {
		t.Error("slow")
	}
	if p.DiscoveryCount() != 1 {
		t.Error("teller")
	}
}

func TestIssuerOverride(t *testing.T) {
	p := New(t, Options{ClientID: cid, Issuer: "http://issuer.example/x"})
	if _, d := discover(t, p); d["issuer"] != "http://issuer.example/x" || p.Issuer() != "http://issuer.example/x" {
		t.Fatal("issuer-override")
	}
}

// AK3.2: oidctest skal ikke havne i produksjonsbinæren, og bare importeres
// fra _test.go og cmd/kauth-testidp.
func TestNotImportedByProduction(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go ikke i PATH")
	}
	run := func(args ...string) string {
		cmd := exec.Command("go", args...)
		cmd.Dir = "../.."
		cmd.Env = append(cmd.Environ(), "CGO_ENABLED=0")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go %v: %v", args, err)
		}
		return string(out)
	}
	if deps := run("list", "-deps", "./cmd/kauth"); strings.Contains(deps, "internal/oidctest") {
		t.Fatal("cmd/kauth avhenger av oidctest")
	}
	for _, line := range strings.Split(run("list", "-f", "{{.ImportPath}} {{join .Imports \" \"}}", "./..."), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasSuffix(f[0], "/internal/oidctest") || strings.HasSuffix(f[0], "/cmd/kauth-testidp") {
			continue
		}
		for _, imp := range f[1:] {
			if strings.HasSuffix(imp, "/internal/oidctest") {
				t.Errorf("%s importerer oidctest utenfor _test.go", f[0])
			}
		}
	}
}

func TestKeysPerInstanceByDefault(t *testing.T) {
	a := New(t, Options{ClientID: cid})
	b := New(t, Options{ClientID: cid})
	if a.keys.rsaKid == b.keys.rsaKid || a.keys.ecKid == b.keys.ecKid {
		t.Fatal("instansene deler nøkler")
	}
	s1 := New(t, Options{ClientID: cid, SharedKeys: true})
	s2 := New(t, Options{ClientID: cid, SharedKeys: true})
	if s1.keys.rsaKid != s2.keys.rsaKid {
		t.Fatal("SharedKeys skal dele nøkler")
	}
	tok := flow(t, a, Claims{Sub: "u"}, ModeOK, [2]string{})["id_token"].(string)
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &b.keys.rsa.PublicKey, KeyID: b.keys.rsaKid}}}
	jws, err := jose.ParseSigned(tok, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jws.Verify(set.Keys[0]); err == nil {
		t.Fatal("token fra A verifiseres av Bs nøkkel")
	}
	if _, err := jws.Verify(&a.keys.rsa.PublicKey); err != nil {
		t.Fatal(err)
	}
}

func TestHS256AlwaysHS256(t *testing.T) {
	for _, secret := range []string{"", "kort"} {
		p := New(t, Options{ClientID: cid, ClientSecret: secret})
		p.Next(Claims{Sub: "u"}, ModeAlgHS256)
		q := authorize(t, p)
		f := tokenForm(q.Get("code"))
		basic := [2]string{}
		if secret != "" {
			basic = [2]string{cid, secret}
		} else {
			f.Set("client_id", cid)
		}
		st, body := postToken(t, p, f, basic)
		if st != 200 || header(t, body["id_token"].(string))["alg"] != "HS256" {
			t.Fatalf("secret %q: %d %v", secret, st, body)
		}
	}
}

func TestTokenRejectsMultipleAuthMethods(t *testing.T) {
	p := New(t, Options{ClientID: cid, ClientSecret: "sec"})
	// Basic og client_secret i skjema samtidig.
	f := tokenForm(authorize(t, p).Get("code"))
	f.Set("client_secret", "sec")
	if st, b := postToken(t, p, f, [2]string{cid, "sec"}); st != 400 || b["error"] != "invalid_request" {
		t.Fatalf("%d %v", st, b)
	}
	// client_id i skjemaet ulik Basic-brukeren.
	f = tokenForm(authorize(t, p).Get("code"))
	f.Set("client_id", "annen")
	if st, b := postToken(t, p, f, [2]string{cid, "sec"}); st != 400 || b["error"] != "invalid_request" {
		t.Fatalf("%d %v", st, b)
	}
	// Lik client_id i skjema og Basic er greit.
	f = tokenForm(authorize(t, p).Get("code"))
	f.Set("client_id", cid)
	if st, _ := postToken(t, p, f, [2]string{cid, "sec"}); st != 200 {
		t.Fatalf("%d", st)
	}
}

func TestCloseIdempotentAndLoopbackOnly(t *testing.T) {
	p, err := NewServer(Options{ClientID: cid})
	if err != nil {
		t.Fatal(err)
	}
	p.Close()
	p.Close()
	for _, a := range []string{"0.0.0.0:0", ":0", "192.168.1.1:0", "example.com:80", "nonsens"} {
		if q, err := NewServer(Options{Addr: a}); err == nil {
			q.Close()
			t.Errorf("%q skal avvises", a)
		}
	}
	for _, a := range []string{"127.0.0.1:0", "localhost:0", "[::1]:0"} {
		q, err := NewServer(Options{Addr: a})
		if err != nil {
			t.Logf("%q: %v (ingen IPv6/localhost her?)", a, err)
			continue
		}
		q.Close()
	}
}

// To fakes uten SharedKeys må ha helt ulike nøkler, og et token fra A skal
// ikke kunne verifiseres mot Bs JWKS selv om iss og aud er like, slik at
// bare signaturen avgjør.
func TestInstancesHaveIndependentKeys(t *testing.T) {
	const issuer = "http://issuer.example"
	a := New(t, Options{ClientID: cid, Issuer: issuer})
	b := New(t, Options{ClientID: cid, Issuer: issuer})

	fetch := func(p *IdP) jose.JSONWebKeySet {
		resp, err := http.Get(p.URL() + "/jwks")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var set jose.JSONWebKeySet
		if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
			t.Fatal(err)
		}
		return set
	}
	sa, sb := fetch(a), fetch(b)
	if len(sa.Keys) != 2 || len(sb.Keys) != 2 {
		t.Fatalf("ventet 2 nøkler hver, fikk %d og %d", len(sa.Keys), len(sb.Keys))
	}
	for i := range sa.Keys {
		if sa.Keys[i].KeyID == sb.Keys[i].KeyID {
			t.Errorf("lik kid %q", sa.Keys[i].KeyID)
		}
		ta, _ := sa.Keys[i].Thumbprint(crypto.SHA256)
		tb, _ := sb.Keys[i].Thumbprint(crypto.SHA256)
		if bytes.Equal(ta, tb) {
			t.Errorf("likt nøkkelmateriale i nøkkel %d", i)
		}
	}

	tok := flow(t, a, Claims{Sub: "u"}, ModeOK, [2]string{})["id_token"].(string)
	// Kontroll: A sitt eget JWKS godtar tokenet med samme iss og aud.
	verify := func(p *IdP) error {
		ks := oidc.NewRemoteKeySet(context.Background(), p.URL()+"/jwks")
		v := oidc.NewVerifier(issuer, ks, &oidc.Config{ClientID: cid})
		_, err := v.Verify(context.Background(), tok)
		return err
	}
	if err := verify(a); err != nil {
		t.Fatalf("kontroll mot eget JWKS: %v", err)
	}
	if err := verify(b); err == nil {
		t.Fatal("token fra A ble verifisert mot Bs JWKS")
	}

	// Pool: etter Close får en ny instans gjenbrukte nøkler, men aldri de
	// samme som en levende instans.
	kidA := a.keys.rsaKid
	a.Close()
	c := New(t, Options{ClientID: cid})
	if c.keys.rsaKid == b.keys.rsaKid {
		t.Fatal("ny instans fikk nøkler fra en levende instans")
	}
	_ = kidA
}
