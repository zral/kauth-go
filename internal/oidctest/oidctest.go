// Package oidctest er en fake OIDC-leverandør for tester. Den kjører på
// httptest.Server (http på loopback) og lar testen styre hva neste innlogging
// gir, inkludert ondsinnede id_token-varianter og ødelagt discovery.
//
// Pakken skal bare importeres fra _test.go og cmd/kauth-testidp, aldri fra
// produksjonskode (K20): den utsteder tokens uten ekte autentisering.
package oidctest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Mode velger hva neste innlogging gjør galt (PD9).
type Mode string

const (
	ModeOK             Mode = "ok"
	ModeWrongIss       Mode = "wrong_iss"
	ModeWrongAud       Mode = "wrong_aud"
	ModeMultiAudBadAzp Mode = "multi_aud_bad_azp"
	ModeWrongNonce     Mode = "wrong_nonce"
	ModeExpired        Mode = "expired"
	ModeUnknownKid     Mode = "unknown_kid"
	ModeAlgNone        Mode = "alg_none"
	ModeAlgHS256       Mode = "alg_hs256"
	ModeRotateKey      Mode = "rotate_key"
	ModeNoIDToken      Mode = "no_id_token"
	ModeAuthorizeError Mode = "authorize_error"
	ModeIssParamWrong  Mode = "iss_param_wrong"
	ModeBadAzp         Mode = "bad_azp"
	ModeToken500       Mode = "token_500"
	ModeTokenSlow      Mode = "token_slow"
)

// DiscoveryMode velger hvordan discovery-dokumentet (og dets URL) feiler.
type DiscoveryMode string

const (
	DiscOK       DiscoveryMode = "ok"
	DiscWrongIss DiscoveryMode = "wrong_issuer"
	// DiscHTTPEndpoint gir authorization_endpoint og token_endpoint på
	// http://idp.example.net. Fake-en selv er http på loopback og kauth tillater
	// da http mot loopback, så et loopback-endepunkt ville ikke vist at
	// https-kravet virker. En ikke-loopback http-vert avvises uansett, og
	// avvises ikke hvis https-sjekken fjernes (mutasjon).
	DiscHTTPEndpoint DiscoveryMode = "http_endpoint"
	DiscRedirect     DiscoveryMode = "redirect"
	// DiscForeignJWKSHost setter jwks_uri til https://10.0.0.1/jwks: gyldig
	// skjema, men en privat adresse. Discovery består; hentingen av nøkler
	// skal stoppes av dial-vakten.
	DiscForeignJWKSHost DiscoveryMode = "foreign_jwks_host"
	DiscHuge            DiscoveryMode = "huge"
	DiscSlow            DiscoveryMode = "slow"
	DiscDown500         DiscoveryMode = "down500"
)

// EmailVerified dekker variantene en leverandør kan sende. Nullverdien er
// boolsk true, så Claims{Sub, Email} gir en verifisert e-post.
type EmailVerified int

const (
	EVTrue        EmailVerified = iota // "email_verified": true
	EVFalse                            // "email_verified": false
	EVStringTrue                       // "email_verified": "true"
	EVStringFalse                      // "email_verified": "false"
	EVOmit                             // feltet utelates
)

// UnmarshalJSON lar kontrollendepunktet i testleverandøren sende true, false,
// "true", "false" eller null (utelat).
func (e *EmailVerified) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch x := v.(type) {
	case nil:
		*e = EVOmit
	case bool:
		if x {
			*e = EVTrue
		} else {
			*e = EVFalse
		}
	case string:
		if strings.EqualFold(x, "true") {
			*e = EVStringTrue
		} else {
			*e = EVStringFalse
		}
	default:
		*e = EVOmit
	}
	return nil
}

// Claims er brukerdataene i neste id_token.
type Claims struct {
	Sub           string        `json:"sub"`
	Email         string        `json:"email"`
	EmailVerified EmailVerified `json:"email_verified"`
	Name          string        `json:"name"`
}

// Options konfigurerer leverandøren.
type Options struct {
	ClientID string
	// ClientSecret tom betyr offentlig klient (ingen klientautentisering).
	ClientSecret  string
	DiscoveryMode DiscoveryMode
	// Issuer overstyrer issuer-verdien i discovery og tokens. Tom bruker URL.
	Issuer string
	// Addr er lytteadressen. Tom gir 127.0.0.1:0.
	Addr string
	// AdvertiseIssParam annonserer authorization_response_iss_parameter_supported
	// i discovery, uavhengig av om authorize-redirecten faktisk har iss.
	AdvertiseIssParam bool
	// IssParam legger iss (RFC 9207) til authorize-redirecten.
	IssParam bool
	// SlowDelay er forsinkelsen i discovery-modusen slow og token_slow.
	// Standard 12 s, altså over klientens tidsavbrudd på 10 s.
	SlowDelay time.Duration
	// Alg er signeringsalgoritmen for vanlige tokens: RS256 (standard) eller ES256.
	Alg string
	// SharedKeys gjør at alle instanser i prosessen bruker samme nøkler. Uten
	// den får hver instans egne nøkler, slik at et token fra én leverandør
	// aldri verifiseres av en annens nøkkelsett.
	SharedKeys bool
	// AuthMethods overstyrer token_endpoint_auth_methods_supported.
	AuthMethods []string
}

// Request er en loggført forespørsel. code_verifier og client_secret er fjernet.
type Request struct {
	Method string     `json:"method"`
	Path   string     `json:"path"`
	Query  url.Values `json:"query"`
	// PKCEValid og ClientAuth er satt for /token.
	PKCEValid  bool   `json:"pkce_valid"`
	ClientAuth string `json:"client_auth,omitempty"` // basic | post | none | invalid
}

type authCode struct {
	clientID, redirectURI, nonce, challenge string
	claims                                  Claims
	mode                                    Mode
}

type keyPair struct {
	rsa    *rsa.PrivateKey
	rsaKid string
	ec     *ecdsa.PrivateKey
	ecKid  string
}

// IdP er en kjørende fake-leverandør.
type IdP struct {
	ClientID string

	opts Options
	srv  *httptest.Server
	done chan struct{}
	once sync.Once

	initKeys keyPair
	held     []keyPair // pool-nøkler som frigis ved Close

	mu        sync.Mutex
	keys      keyPair
	discMode  DiscoveryMode
	next      Claims
	nextMode  Mode
	hasNext   bool
	reqs      []Request
	codes     map[string]*authCode
	discCount int
	jwksCount int
}

var (
	baseOnce sync.Once
	baseKeys keyPair
)

// Nøkkelpoolen gjør at RSA-2048-generering (sekunder på RPi5) betales én gang
// per samtidig instans i prosessen, ikke én gang per test. En instans eier
// sine nøkler til Close, så to levende instanser aldri deler nøkkel.
var (
	poolMu   sync.Mutex
	poolFree []keyPair

	foreignOnce sync.Once
	foreignKeys keyPair
)

func takeKeys() keyPair {
	poolMu.Lock()
	if n := len(poolFree); n > 0 {
		k := poolFree[n-1]
		poolFree = poolFree[:n-1]
		poolMu.Unlock()
		return k
	}
	poolMu.Unlock()
	return newKeyPair()
}

func releaseKeys(ks []keyPair) {
	poolMu.Lock()
	poolFree = append(poolFree, ks...)
	poolMu.Unlock()
}

// foreignKeyPair brukes til å signere unknown_kid; den publiseres aldri.
func foreignKeyPair() keyPair {
	foreignOnce.Do(func() { foreignKeys = newKeyPair() })
	return foreignKeys
}

func newKeyPair() keyPair {
	r, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	e, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return keyPair{rsa: r, rsaKid: kid(&r.PublicKey), ec: e, ecKid: kid(&e.PublicKey)}
}

func kid(pub any) string {
	jwk := jose.JSONWebKey{Key: pub}
	th, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(th)[:16]
}

// New starter en leverandør og stopper den ved testslutt.
func New(t testing.TB, opts Options) *IdP {
	t.Helper()
	p, err := NewServer(opts)
	if err != nil {
		t.Fatalf("oidctest: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

// NewServer er varianten uten testing.TB, for cmd/kauth-testidp. Kall Close.
func NewServer(opts Options) (*IdP, error) {
	if opts.SharedKeys {
		baseOnce.Do(func() { baseKeys = newKeyPair() })
	}
	if opts.DiscoveryMode == "" {
		opts.DiscoveryMode = DiscOK
	}
	if opts.SlowDelay == 0 {
		opts.SlowDelay = 12 * time.Second
	}
	if opts.Alg == "" {
		opts.Alg = "RS256"
	}
	if opts.ClientID == "" {
		opts.ClientID = "test-client"
	}
	addr := opts.Addr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	if !loopbackAddr(addr) {
		return nil, fmt.Errorf("addr %q er ikke loopback", addr)
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	keys := baseKeys
	var held []keyPair
	if !opts.SharedKeys {
		keys = takeKeys()
		held = []keyPair{keys}
	}
	p := &IdP{
		ClientID: opts.ClientID,
		opts:     opts,
		done:     make(chan struct{}),
		keys:     keys,
		initKeys: keys,
		held:     held,
		discMode: opts.DiscoveryMode,
		codes:    map[string]*authCode{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.handleDiscovery)
	mux.HandleFunc("/authorize", p.handleAuthorize)
	mux.HandleFunc("/token", p.handleToken)
	mux.HandleFunc("/jwks", p.handleJWKS)
	p.srv = httptest.NewUnstartedServer(mux)
	p.srv.Listener.Close()
	p.srv.Listener = l
	p.srv.Start()
	return p, nil
}

// Close stopper serveren og avbryter ventende forsinkelser.
func (p *IdP) Close() {
	p.once.Do(func() {
		close(p.done)
		p.srv.Close()
		p.mu.Lock()
		held := p.held
		p.held = nil
		p.mu.Unlock()
		releaseKeys(held)
	})
}

// loopbackAddr: fake-en utsteder tokens uten ekte autentisering og skal aldri
// kunne nås utenfra.
func loopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// URL er basis-URL-en til serveren (der endepunktene faktisk ligger).
func (p *IdP) URL() string { return p.srv.URL }

// Issuer er issuer-verdien leverandøren oppgir.
func (p *IdP) Issuer() string {
	if p.opts.Issuer != "" {
		return p.opts.Issuer
	}
	return p.srv.URL
}

// Next setter claims og modus for neste innlogging. Gjelder én gang, deretter
// brukes standardverdiene igjen.
func (p *IdP) Next(c Claims, mode Mode) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.next, p.nextMode, p.hasNext = c, mode, true
}

// SetDiscoveryMode bytter discovery-modus underveis.
func (p *IdP) SetDiscoveryMode(m DiscoveryMode) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.discMode = m
}

// Reset nullstiller kø, koder, logg, tellere og nøkler.
func (p *IdP) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hasNext, p.next, p.nextMode = false, Claims{}, ""
	p.reqs, p.codes = nil, map[string]*authCode{}
	p.discCount, p.jwksCount = 0, 0
	p.keys = p.initKeys
	p.discMode = p.opts.DiscoveryMode
}

// Requests returnerer en kopi av loggen.
func (p *IdP) Requests() []Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Request(nil), p.reqs...)
}

// DiscoveryCount er antall hentinger av discovery-dokumentet.
func (p *IdP) DiscoveryCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.discCount
}

// JWKSCount er antall hentinger av nøkkelsettet.
func (p *IdP) JWKSCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.jwksCount
}

// RotateKey bytter til nye nøkler med nye kid-er.
func (p *IdP) RotateKey() {
	k := takeKeys()
	p.mu.Lock()
	p.keys = k
	p.held = append(p.held, k)
	p.mu.Unlock()
}

func (p *IdP) log(r *http.Request, mut func(*Request)) {
	q := url.Values{}
	for k, v := range r.URL.Query() {
		q[k] = v
	}
	rec := Request{Method: r.Method, Path: r.URL.Path, Query: q}
	if mut != nil {
		mut(&rec)
	}
	p.mu.Lock()
	p.reqs = append(p.reqs, rec)
	p.mu.Unlock()
}

func (p *IdP) sleep(r *http.Request) {
	select {
	case <-time.After(p.opts.SlowDelay):
	case <-r.Context().Done():
	case <-p.done:
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (p *IdP) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.discCount++
	mode := p.discMode
	p.mu.Unlock()
	p.log(r, nil)

	base := p.srv.URL
	doc := map[string]any{
		"issuer":                                p.Issuer(),
		"authorization_endpoint":                base + "/authorize",
		"token_endpoint":                        base + "/token",
		"jwks_uri":                              base + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256", "ES256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"token_endpoint_auth_methods_supported": p.authMethods(),
	}
	if p.opts.AdvertiseIssParam {
		doc["authorization_response_iss_parameter_supported"] = true
	}
	switch mode {
	case DiscDown500:
		http.Error(w, "down", http.StatusInternalServerError)
		return
	case DiscRedirect:
		http.Redirect(w, r, "http://127.0.0.2:1/.well-known/openid-configuration", http.StatusFound)
		return
	case DiscSlow:
		p.sleep(r)
	case DiscWrongIss:
		doc["issuer"] = base + "/not-the-issuer"
	case DiscHTTPEndpoint:
		doc["authorization_endpoint"] = "http://idp.example.net/authorize"
		doc["token_endpoint"] = "http://idp.example.net/token"
	case DiscForeignJWKSHost:
		doc["jwks_uri"] = "https://10.0.0.1/jwks"
	case DiscHuge:
		doc["padding"] = strings.Repeat("x", 2<<20)
	}
	writeJSON(w, http.StatusOK, doc)
}

func (p *IdP) authMethods() []string {
	if p.opts.AuthMethods != nil {
		return p.opts.AuthMethods
	}
	if p.opts.ClientSecret == "" {
		return []string{"none"}
	}
	return []string{"client_secret_basic", "client_secret_post"}
}

func (p *IdP) handleJWKS(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.jwksCount++
	k := p.keys
	p.mu.Unlock()
	p.log(r, nil)
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &k.rsa.PublicKey, KeyID: k.rsaKid, Algorithm: "RS256", Use: "sig"},
		{Key: &k.ec.PublicKey, KeyID: k.ecKid, Algorithm: "ES256", Use: "sig"},
	}}
	writeJSON(w, http.StatusOK, set)
}

func (p *IdP) takeNext() (Claims, Mode) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.hasNext {
		return Claims{Sub: "test-sub", Email: "user@example.com", Name: "Test User"}, ModeOK
	}
	c, m := p.next, p.nextMode
	p.hasNext = false
	if m == "" {
		m = ModeOK
	}
	return c, m
}

func (p *IdP) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	p.log(r, nil)
	q := r.URL.Query()
	redirect := q.Get("redirect_uri")
	if q.Get("client_id") != p.ClientID || redirect == "" || q.Get("response_type") != "code" ||
		q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "bad authorize request", http.StatusBadRequest)
		return
	}
	ru, err := url.Parse(redirect)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	claims, mode := p.takeNext()
	out := ru.Query()
	if st := q.Get("state"); st != "" {
		out.Set("state", st)
	}
	if mode == ModeAuthorizeError {
		out.Set("error", "access_denied")
		out.Set("error_description", "oidctest-hemmelig-tekst-som-ikke-skal-ekkoes")
		if p.opts.IssParam {
			out.Set("iss", p.Issuer())
		}
		ru.RawQuery = out.Encode()
		http.Redirect(w, r, ru.String(), http.StatusFound)
		return
	}
	code := randHex(16)
	p.mu.Lock()
	p.codes[code] = &authCode{
		clientID: q.Get("client_id"), redirectURI: redirect, nonce: q.Get("nonce"),
		challenge: q.Get("code_challenge"), claims: claims, mode: mode,
	}
	p.mu.Unlock()
	out.Set("code", code)
	switch {
	case mode == ModeIssParamWrong:
		out.Set("iss", "https://evil.example")
	case p.opts.IssParam:
		out.Set("iss", p.Issuer())
	}
	ru.RawQuery = out.Encode()
	http.Redirect(w, r, ru.String(), http.StatusFound)
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (p *IdP) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	rec := Request{Method: r.Method, Path: r.URL.Path, Query: url.Values{}}
	for k, v := range r.PostForm {
		if k == "code_verifier" || k == "client_secret" {
			continue
		}
		rec.Query[k] = v
	}
	finish := func() {
		p.mu.Lock()
		p.reqs = append(p.reqs, rec)
		p.mu.Unlock()
	}
	defer finish()

	clientID, secret, style := r.PostForm.Get("client_id"), "", "none"
	u, pw, hasBasic := r.BasicAuth()
	formSecret := r.PostForm.Get("client_secret")
	if hasBasic {
		bu, _ := url.QueryUnescape(u)
		// RFC 6749 §2.3: én metode per forespørsel, og client_id må stemme.
		if formSecret != "" || (clientID != "" && clientID != bu) {
			rec.ClientAuth = "invalid"
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		clientID = bu
		secret, _ = url.QueryUnescape(pw)
		style = "basic"
	} else if formSecret != "" {
		secret, style = formSecret, "post"
	}
	rec.ClientAuth = style
	if clientID != p.ClientID {
		rec.ClientAuth = "invalid"
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if p.opts.ClientSecret != "" &&
		subtle.ConstantTimeCompare([]byte(secret), []byte(p.opts.ClientSecret)) != 1 {
		rec.ClientAuth = "invalid"
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	// Koden brennes ved første oppslag, også når resten feiler (RFC 6749 §4.1.2).
	p.mu.Lock()
	ac := p.codes[r.PostForm.Get("code")]
	delete(p.codes, r.PostForm.Get("code"))
	p.mu.Unlock()
	if ac == nil || ac.clientID != clientID || ac.redirectURI != r.PostForm.Get("redirect_uri") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	rec.PKCEValid = r.PostForm.Get("code_verifier") != "" &&
		subtle.ConstantTimeCompare([]byte(want), []byte(ac.challenge)) == 1
	if !rec.PKCEValid {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	switch ac.mode {
	case ModeToken500:
		http.Error(w, "boom", http.StatusInternalServerError)
		return
	case ModeTokenSlow:
		p.sleep(r)
	case ModeRotateKey:
		p.RotateKey()
	}
	resp := map[string]any{
		"access_token": "at-" + randHex(8),
		"token_type":   "Bearer",
		"expires_in":   3600,
	}
	if ac.mode != ModeNoIDToken {
		tok, err := p.signIDToken(ac)
		if err != nil {
			http.Error(w, "sign", http.StatusInternalServerError)
			return
		}
		resp["id_token"] = tok
	}
	writeJSON(w, http.StatusOK, resp)
}

func (p *IdP) signIDToken(ac *authCode) (string, error) {
	now := time.Now()
	c := ac.claims
	payload := map[string]any{
		"iss": p.Issuer(),
		"sub": c.Sub,
		"aud": ac.clientID,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
	if ac.nonce != "" {
		payload["nonce"] = ac.nonce
	}
	if c.Email != "" {
		payload["email"] = c.Email
	}
	if c.Name != "" {
		payload["name"] = c.Name
	}
	switch c.EmailVerified {
	case EVTrue:
		payload["email_verified"] = true
	case EVFalse:
		payload["email_verified"] = false
	case EVStringTrue:
		payload["email_verified"] = "true"
	case EVStringFalse:
		payload["email_verified"] = "false"
	}
	p.mu.Lock()
	k := p.keys
	p.mu.Unlock()

	alg, key := jose.SignatureAlgorithm(p.opts.Alg), any(nil)
	kidv := ""
	if alg == jose.ES256 {
		key, kidv = k.ec, k.ecKid
	} else {
		alg, key, kidv = jose.RS256, k.rsa, k.rsaKid
	}

	switch ac.mode {
	case ModeWrongIss:
		payload["iss"] = "https://evil.example"
	case ModeWrongAud:
		payload["aud"] = "some-other-client"
	case ModeMultiAudBadAzp:
		payload["aud"] = []string{ac.clientID, "some-other-client"}
		payload["azp"] = "some-other-client"
	case ModeBadAzp:
		payload["azp"] = "some-other-client"
	case ModeWrongNonce:
		payload["nonce"] = "wrong-nonce"
	case ModeExpired:
		payload["iat"] = now.Add(-2 * time.Hour).Unix()
		payload["exp"] = now.Add(-time.Hour).Unix()
	case ModeUnknownKid:
		other := foreignKeyPair()
		key, kidv = other.rsa, "unknown-kid"
		alg = jose.RS256
	case ModeAlgNone:
		h, _ := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
		b, _ := json.Marshal(payload)
		return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(b) + ".", nil
	case ModeAlgHS256:
		alg, kidv = jose.HS256, k.rsaKid
		if len(p.opts.ClientSecret) >= 32 {
			// go-jose krever minst 32 byte HMAC-nøkkel; kortere eller manglende
			// hemmelighet faller tilbake til modulusen så modusen alltid gir HS256.
			key = []byte(p.opts.ClientSecret)
		} else {
			// Klassisk nøkkelforvekslingsangrep: den offentlige RSA-modulusen
			// brukt som HMAC-nøkkel.
			key = k.rsa.PublicKey.N.Bytes()
		}
	}

	opts := (&jose.SignerOptions{}).WithType("JWT")
	sk := jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{Key: key, KeyID: kidv}}
	s, err := jose.NewSigner(sk, opts)
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(payload)
	jws, err := s.Sign(b)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}
