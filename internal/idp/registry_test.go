package idp

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/zral/kauth-go/internal/oidctest"
	"golang.org/x/oauth2"
)

const testClientID = "kauth-test"

func newFake(t *testing.T, o oidctest.Options) *oidctest.IdP {
	t.Helper()
	if o.ClientID == "" {
		o.ClientID = testClientID
	}
	return oidctest.New(t, o)
}

func provider(f *oidctest.IdP, secret string) Provider {
	return Provider{ID: 1, Slug: "fake", Issuer: f.Issuer(), ClientID: f.ClientID, ClientSecret: secret, Scopes: []string{"openid"}}
}

func newReg(t *testing.T, p Provider) *Registry {
	t.Helper()
	r := NewRegistry(map[string]Provider{p.Slug: p}, map[string][]string{"svc": {p.Slug}}, NewHTTPClient(true), true)
	return r
}

// clock er en injiserbar tid.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// settle venter til bakgrunnshentingen for slug er ferdig.
func settle(t *testing.T, r *Registry, slug string) {
	t.Helper()
	e := r.entries[slug]
	deadline := time.Now().Add(5 * time.Second)
	for {
		e.mu.Lock()
		idle := e.inflight == nil
		e.mu.Unlock()
		if idle {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("bakgrunnshentingen ble ikke ferdig")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// shortCtx gjør at en Discover som henger (mutant) feiler raskt.
func shortCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func withClock(r *Registry) *clock {
	c := &clock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	r.now = c.now
	return c
}

func TestDiscoverOK(t *testing.T) {
	f := newFake(t, oidctest.Options{ClientSecret: "s3"})
	r := newReg(t, provider(f, "s3"))
	d, err := r.Discover(context.Background(), "fake")
	if err != nil {
		t.Fatal(err)
	}
	if d.Endpoint.TokenURL != f.URL()+"/token" || d.Endpoint.AuthURL != f.URL()+"/authorize" {
		t.Fatalf("endpoint: %+v", d.Endpoint)
	}
	if d.Endpoint.AuthStyle != oauth2.AuthStyleInHeader {
		t.Fatalf("authstyle: %v", d.Endpoint.AuthStyle)
	}
	if strings.Join(d.Algs, ",") != "RS256,ES256" {
		t.Fatalf("algs: %v", d.Algs)
	}
	if r.Client() == nil {
		t.Fatal("Client() er nil")
	}
	if _, err := r.Discover(context.Background(), "ukjent"); err == nil {
		t.Fatal("ukjent slug skal feile")
	}
}

func TestDiscoverRejectsBadDocuments(t *testing.T) {
	for _, m := range []oidctest.DiscoveryMode{
		oidctest.DiscWrongIss, oidctest.DiscHTTPEndpoint, oidctest.DiscRedirect,
		oidctest.DiscHuge, oidctest.DiscDown500,
	} {
		t.Run(string(m), func(t *testing.T) {
			f := newFake(t, oidctest.Options{DiscoveryMode: m})
			r := newReg(t, provider(f, ""))
			if d, err := r.Discover(context.Background(), "fake"); err == nil {
				t.Fatalf("ventet feil, fikk %+v", d)
			}
		})
	}
}

func TestDiscoverSlowHitsTimeout(t *testing.T) {
	f := newFake(t, oidctest.Options{DiscoveryMode: oidctest.DiscSlow, SlowDelay: 3 * time.Second})
	r := newReg(t, provider(f, ""))
	r.timeout = 200 * time.Millisecond
	start := time.Now()
	if _, err := r.Discover(context.Background(), "fake"); err == nil {
		t.Fatal("ventet tidsavbrudd")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("tok for lang tid: %v", time.Since(start))
	}
}

func TestDiscoverCallerCanCancelWait(t *testing.T) {
	f := newFake(t, oidctest.Options{DiscoveryMode: oidctest.DiscSlow, SlowDelay: 2 * time.Second})
	r := newReg(t, provider(f, ""))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := r.Discover(ctx, "fake")
	if err != context.DeadlineExceeded {
		t.Fatalf("ventet DeadlineExceeded, fikk %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("kalleren ventet for lenge")
	}
}

// En avbrutt request-kontekst skal ikke ødelegge nøkkelhenting senere.
func TestDiscoverIndependentOfCallerContext(t *testing.T) {
	f := newFake(t, oidctest.Options{})
	r := newReg(t, provider(f, ""))
	ctx, cancel := context.WithCancel(context.Background())
	d, err := r.Discover(ctx, "fake")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := login(t, f, r, d, "fake", oidctest.Claims{Sub: "a"}, oidctest.ModeOK); err != nil {
		t.Fatalf("verifisering etter avbrutt kontekst: %v", err)
	}
}

func TestForeignJWKSHostBlockedAtFetch(t *testing.T) {
	f := newFake(t, oidctest.Options{DiscoveryMode: oidctest.DiscForeignJWKSHost})
	r := newReg(t, provider(f, ""))
	d, err := r.Discover(context.Background(), "fake")
	if err != nil {
		t.Fatalf("discovery skal bestå, vakten stopper hentingen: %v", err)
	}
	f.SetDiscoveryMode(oidctest.DiscOK)
	if _, err := login(t, f, r, d, "fake", oidctest.Claims{Sub: "a"}, oidctest.ModeOK); err == nil {
		t.Fatal("verifisering mot privat jwks-vert skal feile")
	}
}

func TestDiscoveryCachedAndRenewed(t *testing.T) {
	f := newFake(t, oidctest.Options{})
	r := newReg(t, provider(f, ""))
	clk := withClock(r)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := r.Discover(ctx, "fake"); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.DiscoveryCount(); n != 1 {
		t.Fatalf("ventet 1 henting, fikk %d", n)
	}
	clk.add(23 * time.Hour)
	r.Discover(ctx, "fake")
	if n := f.DiscoveryCount(); n != 1 {
		t.Fatalf("23 t: ventet 1, fikk %d", n)
	}
	clk.add(2 * time.Hour)
	old, err := r.Discover(ctx, "fake")
	if err != nil {
		t.Fatal(err)
	}
	settle(t, r, "fake")
	if n := f.DiscoveryCount(); n != 2 {
		t.Fatalf("etter 25 t: ventet 2, fikk %d", n)
	}
	if nu, _ := r.Discover(ctx, "fake"); nu == old || f.DiscoveryCount() != 2 {
		t.Fatal("ventet ny verdi uten ny henting")
	}
}

func TestRenewalFailureUsesPreviousUpTo7Days(t *testing.T) {
	f := newFake(t, oidctest.Options{})
	r := newReg(t, provider(f, ""))
	clk := withClock(r)
	ctx := context.Background()
	first, err := r.Discover(ctx, "fake")
	if err != nil {
		t.Fatal(err)
	}
	f.SetDiscoveryMode(oidctest.DiscDown500)
	clk.add(25 * time.Hour)
	d, err := r.Discover(ctx, "fake")
	if err != nil || d != first {
		t.Fatalf("ventet forrige verdi, fikk %v %v", d, err)
	}
	settle(t, r, "fake")
	n := f.DiscoveryCount()
	if n != 2 {
		t.Fatalf("ventet 2 hentinger, fikk %d", n)
	}
	// Innenfor negativ cache: ingen ny henting, fortsatt forrige verdi.
	clk.add(30 * time.Second)
	if d, err := r.Discover(ctx, "fake"); err != nil || d != first {
		t.Fatalf("negativ cache: %v %v", d, err)
	}
	if f.DiscoveryCount() != n {
		t.Fatal("negativ cache hentet på nytt")
	}
	// Etter 7 døgn er forrige verdi for gammel.
	clk.add(7 * 24 * time.Hour)
	if _, err := r.Discover(shortCtx(t), "fake"); err == nil {
		t.Fatal("forrige verdi eldre enn 7 døgn skal ikke brukes")
	}
	// Leverandøren er tilbake: etter negativ cache hentes den på nytt.
	f.SetDiscoveryMode(oidctest.DiscOK)
	clk.add(61 * time.Second)
	if d, err := r.Discover(shortCtx(t), "fake"); err != nil || d == first {
		t.Fatalf("ventet ny verdi: %v %v", d, err)
	}
}

func TestNegativeCache60s(t *testing.T) {
	f := newFake(t, oidctest.Options{DiscoveryMode: oidctest.DiscDown500})
	r := newReg(t, provider(f, ""))
	clk := withClock(r)
	ctx := context.Background()
	if _, err := r.Discover(ctx, "fake"); err == nil {
		t.Fatal("ventet feil")
	}
	for i := 0; i < 5; i++ {
		r.Discover(ctx, "fake")
	}
	if n := f.DiscoveryCount(); n != 1 {
		t.Fatalf("negativ cache: ventet 1 henting, fikk %d", n)
	}
	clk.add(59 * time.Second)
	r.Discover(ctx, "fake")
	if n := f.DiscoveryCount(); n != 1 {
		t.Fatalf("59 s: ventet 1, fikk %d", n)
	}
	clk.add(2 * time.Second)
	r.Discover(ctx, "fake")
	if n := f.DiscoveryCount(); n != 2 {
		t.Fatalf("61 s: ventet 2, fikk %d", n)
	}
}

func TestConcurrentDiscoverSingleFetch(t *testing.T) {
	f := newFake(t, oidctest.Options{})
	r := newReg(t, provider(f, ""))
	var wg sync.WaitGroup
	var fails atomic.Int32
	start := make(chan struct{})
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := r.Discover(context.Background(), "fake"); err != nil {
				fails.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if fails.Load() != 0 {
		t.Fatalf("%d feilet", fails.Load())
	}
	if n := f.DiscoveryCount(); n != 1 {
		t.Fatalf("20 goroutiner: ventet 1 henting, fikk %d", n)
	}
}

func TestIntersectAlgs(t *testing.T) {
	ptr := func(s ...string) *[]string { return &s }
	got, err := intersectAlgs(nil)
	if err != nil || len(got) != 1 || got[0] != "RS256" {
		t.Fatalf("manglende felt: %v %v", got, err)
	}
	got, err = intersectAlgs(ptr("HS256", "none", "ES256", "RS256", "HS512"))
	if err != nil || strings.Join(got, ",") != "ES256,RS256" {
		t.Fatalf("filtrering: %v %v", got, err)
	}
	for _, in := range [][]string{{"HS256"}, {"none"}, {"HS256", "none"}, {}} {
		if _, err := intersectAlgs(ptr(in...)); err == nil {
			t.Fatalf("%v skal gi feil", in)
		}
	}
}

func TestAuthStyleSelection(t *testing.T) {
	cases := []struct {
		secret  string
		methods []string
		want    oauth2.AuthStyle
		wantErr bool
	}{
		{"s", nil, oauth2.AuthStyleInHeader, false},
		{"s", []string{"client_secret_post", "client_secret_basic"}, oauth2.AuthStyleInHeader, false},
		{"s", []string{"client_secret_post"}, oauth2.AuthStyleInParams, false},
		{"s", []string{"private_key_jwt"}, 0, true},
		{"", []string{"client_secret_basic"}, oauth2.AuthStyleInParams, false},
		{"", []string{"none"}, oauth2.AuthStyleInParams, false},
	}
	for i, c := range cases {
		got, err := authStyle(Provider{ClientSecret: c.secret}, c.methods)
		if (err != nil) != c.wantErr || (!c.wantErr && got != c.want) {
			t.Errorf("case %d: %v %v", i, got, err)
		}
	}
}

func TestAuthStyleFromDiscovery(t *testing.T) {
	f := newFake(t, oidctest.Options{ClientSecret: "s3", AuthMethods: []string{"client_secret_post"}})
	d, err := newReg(t, provider(f, "s3")).Discover(context.Background(), "fake")
	if err != nil || d.Endpoint.AuthStyle != oauth2.AuthStyleInParams {
		t.Fatalf("%+v %v", d, err)
	}
	f2 := newFake(t, oidctest.Options{})
	d, err = newReg(t, provider(f2, "")).Discover(context.Background(), "fake")
	if err != nil || d.Endpoint.AuthStyle != oauth2.AuthStyleInParams {
		t.Fatalf("offentlig klient: %+v %v", d, err)
	}
}

func TestEndpointOK(t *testing.T) {
	strict := &Registry{}
	loose := &Registry{allowInsecure: true}
	cases := []struct {
		u            string
		strict, lose bool
	}{
		{"https://idp.example.com/x", true, true},
		{"http://127.0.0.1:8080/x", false, true},
		{"http://localhost/x", false, true},
		{"http://[::1]:80/x", false, true},
		{"http://idp.example.net/x", false, false},
		{"http://10.0.0.1/x", false, false},
		{"ftp://127.0.0.1/x", false, false},
		{"", false, false},
		{"https:///x", false, false},
		{"https://u:p@idp.example.com/", false, false},
	}
	for _, c := range cases {
		if got := strict.endpointOK(c.u); got != c.strict {
			t.Errorf("strict %q = %v", c.u, got)
		}
		if got := loose.endpointOK(c.u); got != c.lose {
			t.Errorf("loose %q = %v", c.u, got)
		}
	}
}

// AK3.5: avvist eller ukjent slug i byService gir ingen leverandør.
func TestForServiceSkipsUnloaded(t *testing.T) {
	a := Provider{ID: 1, Slug: "a"}
	b := Provider{ID: 2, Slug: "b"}
	r := NewRegistry(
		map[string]Provider{"a": a, "b": b},
		map[string][]string{"svc": {"b", "avvist", "a", "ukjent"}, "tom": {"avvist"}},
		NewHTTPClient(false), false,
	)
	got := r.ForService("svc")
	if len(got) != 2 || got[0].Slug != "b" || got[1].Slug != "a" {
		t.Fatalf("rekkefølge/filtrering: %v", got)
	}
	if len(r.ForService("tom")) != 0 || len(r.ForService("nei")) != 0 {
		t.Fatal("ventet ingen leverandører")
	}
	if _, ok := r.Get("avvist"); ok {
		t.Fatal("Get(avvist) skal være false")
	}
	if p, ok := r.Get("a"); !ok || p.ID != 1 {
		t.Fatal("Get(a)")
	}
}

// login kjører authorize og kodeutveksling mot fake-en slik F4 vil gjøre, og
// verifiserer id_token med registerets verifiserer.
func login(t *testing.T, f *oidctest.IdP, r *Registry, d *Discovered, slug string, c oidctest.Claims, m oidctest.Mode) (string, error) {
	t.Helper()
	p, _ := r.Get(slug)
	f.Next(c, m)
	cfg := &oauth2.Config{
		ClientID: p.ClientID, ClientSecret: p.ClientSecret, Endpoint: d.Endpoint,
		RedirectURL: "http://127.0.0.1:1/idp/fake/callback", Scopes: p.Scopes,
	}
	verifier := PKCEVerifier([]byte("hemmelig"), "state1")
	au := cfg.AuthCodeURL("state1", oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", "n-1"))
	nr := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := nr.Get(au)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || loc.Query().Get("code") == "" {
		t.Fatalf("ingen kode i %q", resp.Header.Get("Location"))
	}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, r.Client())
	tok, err := cfg.Exchange(ctx, loc.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := d.Verifier(p.ClientID).Verify(ctx, raw)
	if err != nil {
		return raw, err
	}
	var cl struct {
		Nonce string `json:"nonce"`
	}
	idt.Claims(&cl)
	if cl.Nonce != "n-1" {
		return raw, context.Canceled // nonce-feil; F4 sjekker nonce selv
	}
	return raw, nil
}

func TestVerifierAcceptsAndRejects(t *testing.T) {
	cases := []struct {
		mode   oidctest.Mode
		secret string
		wantOK bool
	}{
		{oidctest.ModeOK, "", true},
		{oidctest.ModeOK, "s3", true},
		{oidctest.ModeWrongIss, "", false},
		{oidctest.ModeWrongAud, "", false},
		{oidctest.ModeWrongNonce, "", false},
		{oidctest.ModeExpired, "", false},
		{oidctest.ModeUnknownKid, "", false},
		{oidctest.ModeAlgNone, "", false},
		{oidctest.ModeAlgHS256, "", false},                                          // RSA-modulus som HMAC-nøkkel
		{oidctest.ModeAlgHS256, "client-secret-0123456789-abcdefghijklmnop", false}, // klienthemmeligheten som nøkkel
		{oidctest.ModeRotateKey, "", true},
	}
	for _, c := range cases {
		t.Run(string(c.mode)+"/"+c.secret, func(t *testing.T) {
			f := newFake(t, oidctest.Options{ClientSecret: c.secret})
			r := newReg(t, provider(f, c.secret))
			d, err := r.Discover(context.Background(), "fake")
			if err != nil {
				t.Fatal(err)
			}
			_, err = login(t, f, r, d, "fake", oidctest.Claims{Sub: "a", Email: "a@example.com"}, c.mode)
			if (err == nil) != c.wantOK {
				t.Fatalf("wantOK=%v err=%v", c.wantOK, err)
			}
		})
	}
}

func TestVerifierES256(t *testing.T) {
	f := newFake(t, oidctest.Options{Alg: "ES256"})
	r := newReg(t, provider(f, ""))
	d, err := r.Discover(context.Background(), "fake")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := login(t, f, r, d, "fake", oidctest.Claims{Sub: "a"}, oidctest.ModeOK); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownKidRefetchesJWKSOnce(t *testing.T) {
	f := newFake(t, oidctest.Options{})
	r := newReg(t, provider(f, ""))
	d, _ := r.Discover(context.Background(), "fake")
	if _, err := login(t, f, r, d, "fake", oidctest.Claims{Sub: "a"}, oidctest.ModeOK); err != nil {
		t.Fatal(err)
	}
	if n := f.JWKSCount(); n != 1 {
		t.Fatalf("første verifisering: ventet 1 JWKS-henting, fikk %d", n)
	}
	if _, err := login(t, f, r, d, "fake", oidctest.Claims{Sub: "a"}, oidctest.ModeUnknownKid); err == nil {
		t.Fatal("ukjent kid skal feile")
	}
	if n := f.JWKSCount(); n != 2 {
		t.Fatalf("ukjent kid: ventet nøyaktig én ny henting (2), fikk %d", n)
	}
}

func TestKeyRotationRefetchesJWKSOnce(t *testing.T) {
	f := newFake(t, oidctest.Options{})
	r := newReg(t, provider(f, ""))
	d, _ := r.Discover(context.Background(), "fake")
	if _, err := login(t, f, r, d, "fake", oidctest.Claims{Sub: "a"}, oidctest.ModeOK); err != nil {
		t.Fatal(err)
	}
	if _, err := login(t, f, r, d, "fake", oidctest.Claims{Sub: "a"}, oidctest.ModeRotateKey); err != nil {
		t.Fatalf("rotert nøkkel skal verifiseres etter ny henting: %v", err)
	}
	if n := f.JWKSCount(); n != 2 {
		t.Fatalf("ventet 2 JWKS-hentinger, fikk %d", n)
	}
	// Den nye nøkkelen er nå cachet.
	if _, err := login(t, f, r, d, "fake", oidctest.Claims{Sub: "a"}, oidctest.ModeOK); err != nil {
		t.Fatal(err)
	}
	if n := f.JWKSCount(); n != 2 {
		t.Fatalf("ventet fortsatt 2, fikk %d", n)
	}
}

func TestStaleWhileRevalidate(t *testing.T) {
	f := newFake(t, oidctest.Options{SlowDelay: 500 * time.Millisecond})
	r := newReg(t, provider(f, ""))
	clk := withClock(r)
	first, err := r.Discover(shortCtx(t), "fake")
	if err != nil {
		t.Fatal(err)
	}
	f.SetDiscoveryMode(oidctest.DiscSlow)
	clk.add(25 * time.Hour)
	start := time.Now()
	d, err := r.Discover(shortCtx(t), "fake")
	if err != nil || d != first {
		t.Fatalf("ventet forrige verdi: %v %v", d, err)
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatalf("ventet på hentingen: %v", time.Since(start))
	}
	// Flere kall under pågående fornyelse starter ikke flere hentinger.
	for i := 0; i < 5; i++ {
		r.Discover(shortCtx(t), "fake")
	}
	settle(t, r, "fake")
	if n := f.DiscoveryCount(); n != 2 {
		t.Fatalf("ventet 2 hentinger, fikk %d", n)
	}
	if nu, _ := r.Discover(shortCtx(t), "fake"); nu == first {
		t.Fatal("verdien skal være fornyet")
	}
}

func TestZeroTTLDoesNotHang(t *testing.T) {
	f := newFake(t, oidctest.Options{})
	r := newReg(t, provider(f, ""))
	clk := withClock(r)
	r.Discover(shortCtx(t), "fake")
	clk.add(discoveryMaxAge + time.Hour)
	if _, err := r.Discover(shortCtx(t), "fake"); err != nil {
		t.Fatal(err)
	}
	if n := f.DiscoveryCount(); n != 2 {
		t.Fatalf("ventet 2 hentinger, fikk %d", n)
	}
}

// Kallerens avbrutte kontekst skal ikke avbryte hentingen.
func TestCancelledCallerFetchCompletesInBackground(t *testing.T) {
	f := newFake(t, oidctest.Options{DiscoveryMode: oidctest.DiscSlow, SlowDelay: 400 * time.Millisecond})
	r := newReg(t, provider(f, ""))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := r.Discover(ctx, "fake"); err != context.DeadlineExceeded {
		t.Fatalf("ventet DeadlineExceeded, fikk %v", err)
	}
	settle(t, r, "fake")
	d, err := r.Discover(shortCtx(t), "fake")
	if err != nil || d == nil {
		t.Fatalf("ventet verdi fra bakgrunnshentingen: %v", err)
	}
	if n := f.DiscoveryCount(); n != 1 {
		t.Fatalf("ventet 1 henting, fikk %d", n)
	}
}

func TestDiscoveryReasonClassification(t *testing.T) {
	cases := []struct {
		mode   oidctest.DiscoveryMode
		reason string
	}{
		{oidctest.DiscWrongIss, "issuer_mismatch"},
		{oidctest.DiscHTTPEndpoint, "endpoint_scheme"},
		{oidctest.DiscRedirect, "redirect"},
		{oidctest.DiscHuge, "too_large"},
		{oidctest.DiscDown500, "http_status"},
		{oidctest.DiscSlow, "timeout"},
	}
	for _, c := range cases {
		t.Run(c.reason, func(t *testing.T) {
			f := newFake(t, oidctest.Options{DiscoveryMode: c.mode, SlowDelay: 2 * time.Second})
			r := newReg(t, provider(f, ""))
			r.timeout = 200 * time.Millisecond
			_, err := r.Discover(shortCtx(t), "fake")
			if got := DiscoveryReason(err); got != c.reason {
				t.Fatalf("reason %q, ventet %q (%v)", got, c.reason, err)
			}
			if !errors.Is(err, ErrDiscovery) {
				t.Fatal("skal matche ErrDiscovery")
			}
		})
	}
	// Privat adresse: vakten stopper dialen.
	p := Provider{ID: 1, Slug: "x", Issuer: "https://127.0.0.1:1"}
	r := NewRegistry(map[string]Provider{"x": p}, nil, NewHTTPClient(false), false)
	_, err := r.Discover(shortCtx(t), "x")
	if got := DiscoveryReason(err); got != "blocked_address" {
		t.Fatalf("blocked: %q (%v)", got, err)
	}
	if _, err := intersectAlgs(&[]string{"HS256"}); DiscoveryReason(err) != "no_algs" {
		t.Fatal("no_algs")
	}
	if _, err := authStyle(Provider{ClientSecret: "s"}, []string{"private_key_jwt"}); DiscoveryReason(err) != "auth_method" {
		t.Fatal("auth_method")
	}
	if DiscoveryReason(nil) != "" || DiscoveryReason(errors.New("noe")) != "fetch" {
		t.Fatal("nil/fetch")
	}
	// Feilteksten skal ikke inneholde noe fra leverandøren.
	f := newFake(t, oidctest.Options{DiscoveryMode: oidctest.DiscDown500})
	_, err = newReg(t, provider(f, "")).Discover(shortCtx(t), "fake")
	if strings.Contains(err.Error(), "down") {
		t.Fatalf("lekker svarkropp: %v", err)
	}
}

func TestFetchPanicBecomesError(t *testing.T) {
	f := newFake(t, oidctest.Options{})
	r := newReg(t, provider(f, ""))
	r.discoverFn = func(Provider) (*Discovered, error) { panic("boom") }
	_, err := r.Discover(shortCtx(t), "fake")
	if DiscoveryReason(err) != "fetch" {
		t.Fatalf("ventet reason fetch, fikk %v", err)
	}
}

func TestExchangeGoesThroughGuardedClient(t *testing.T) {
	f := newFake(t, oidctest.Options{})
	p := provider(f, "")
	// Strengt register (allowInsecure=false): loopback skal avvises av klienten.
	r := NewRegistry(map[string]Provider{"fake": p}, nil, NewHTTPClient(false), false)
	cfg := &oauth2.Config{
		ClientID: p.ClientID,
		Endpoint: oauth2.Endpoint{TokenURL: f.URL() + "/token", AuthStyle: oauth2.AuthStyleInParams},
	}
	if _, err := r.Exchange(context.Background(), "fake", cfg, "kode"); err == nil {
		t.Fatal("exchange mot loopback skal avvises av vakten")
	}
	for _, rq := range f.Requests() {
		if rq.Path == "/token" {
			t.Fatal("forespørselen nådde leverandøren")
		}
	}
	if _, err := r.Exchange(context.Background(), "ukjent", cfg, "kode"); err != ErrUnknownProvider {
		t.Fatalf("ukjent slug: %v", err)
	}
	ctx := r.HTTPContext(context.Background())
	if ctx.Value(oauth2.HTTPClient) != r.Client() {
		t.Fatal("oauth2.HTTPClient mangler")
	}
	if _, err := oidc.NewProvider(ctx, f.URL()); err == nil {
		t.Fatal("oidc-konteksten skal bruke vaktet klient")
	}
}

// Mutant: TTL=0 eller en cache som ikke brukes skal gi rød test.
func TestTTLRespectedManyCalls(t *testing.T) {
	f := newFake(t, oidctest.Options{})
	r := newReg(t, provider(f, ""))
	clk := withClock(r)
	for i := 0; i < 50; i++ {
		if _, err := r.Discover(shortCtx(t), "fake"); err != nil {
			t.Fatal(err)
		}
		settle(t, r, "fake")
		clk.add(10 * time.Minute) // til sammen 8 t 20 min
	}
	if n := f.DiscoveryCount(); n != 1 {
		t.Fatalf("innenfor 24 t: ventet 1 henting, fikk %d", n)
	}
	clk.add(24 * time.Hour)
	for i := 0; i < 20; i++ {
		r.Discover(shortCtx(t), "fake")
	}
	settle(t, r, "fake")
	if n := f.DiscoveryCount(); n != 2 {
		t.Fatalf("etter 24 t: ventet nøyaktig 1 fornyelse (2 totalt), fikk %d", n)
	}
	for i := 0; i < 20; i++ {
		r.Discover(shortCtx(t), "fake")
	}
	settle(t, r, "fake")
	if n := f.DiscoveryCount(); n != 2 {
		t.Fatalf("ventet fortsatt 2, fikk %d", n)
	}
}
