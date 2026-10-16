package idp

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	discoveryTTL     = 24 * time.Hour
	discoveryMaxAge  = 7 * 24 * time.Hour
	discoveryNegTTL  = 60 * time.Second
	discoveryTimeout = 10 * time.Second
)

var (
	ErrUnknownProvider = errors.New("idp: ukjent leverandør")
	ErrDiscovery       = errors.New("idp: discovery feilet")
)

// allowedAlgs er signaturalgoritmene vi stoler på. HS256 og none er med vilje
// utelatt: en HMAC-nøkkel avledet av klienthemmeligheten eller den offentlige
// modulusen gjør at en angriper kan forfalske tokens (algoritmeforveksling).
var allowedAlgs = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"PS256": true, "PS384": true, "PS512": true,
	"ES256": true, "ES384": true, "ES512": true,
	"EdDSA": true,
}

// Discovered er resultatet av en vellykket discovery.
type Discovered struct {
	Provider *oidc.Provider
	Endpoint oauth2.Endpoint
	Algs     []string
}

// Verifier lager en id_token-verifiserer bundet til klient-ID og de
// algoritmene leverandøren faktisk annonserte (snittet over).
func (d *Discovered) Verifier(clientID string) *oidc.IDTokenVerifier {
	return d.Provider.Verifier(&oidc.Config{ClientID: clientID, SupportedSigningAlgs: d.Algs})
}

// flight er én pågående henting. Ventende kallere bruker resultatet herfra
// uansett alder, så ingen løkke kan spinne.
type flight struct {
	done chan struct{}
	d    *Discovered
	err  error
}

type entry struct {
	mu         sync.Mutex
	d          *Discovered
	fetchedAt  time.Time
	lastErr    error
	retryAfter time.Time
	inflight   *flight
}

// DiscoveryError bærer en klassifisert årsak. Den rå feilteksten fra go-oidc
// kan inneholde svarkroppen fra leverandøren og tas aldri med.
type DiscoveryError struct{ Reason string }

func (e *DiscoveryError) Error() string        { return "idp: discovery feilet: " + e.Reason }
func (e *DiscoveryError) Is(target error) bool { return target == ErrDiscovery }

func discErr(reason string) error { return &DiscoveryError{Reason: reason} }

var httpStatusRe = regexp.MustCompile(`^\d{3} `)

// DiscoveryReason klassifiserer en feil fra Discover: timeout, too_large,
// redirect, blocked_address, http_status, issuer_mismatch, endpoint_scheme,
// no_algs, auth_method eller fetch. Tom streng for nil.
func DiscoveryReason(err error) string {
	if err == nil {
		return ""
	}
	var de *DiscoveryError
	if errors.As(err, &de) {
		return de.Reason
	}
	var ne net.Error
	msg := err.Error()
	switch {
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) ||
		strings.Contains(msg, "context deadline exceeded") || strings.Contains(msg, "Client.Timeout"):
		return "timeout"
	case errors.Is(err, errBodyTooLarge) || strings.Contains(msg, errBodyTooLarge.Error()):
		return "too_large"
	case strings.Contains(msg, "redirect avvist"):
		return "redirect"
	case strings.Contains(msg, "ikke tillatt som utgående mål") || strings.Contains(msg, "dial uten IP-adresse"):
		return "blocked_address"
	case strings.Contains(msg, "bare https er tillatt"):
		return "endpoint_scheme"
	case strings.Contains(msg, "did not match the issuer URL"):
		return "issuer_mismatch"
	case httpStatusRe.MatchString(msg):
		return "http_status"
	}
	return "fetch"
}

// Registry holder lastede leverandører og en discovery-cache per slug.
type Registry struct {
	providers     map[string]Provider
	byService     map[string][]string
	client        *http.Client
	allowInsecure bool
	entries       map[string]*entry

	now        func() time.Time
	timeout    time.Duration
	discoverFn func(Provider) (*Discovered, error)
}

// NewRegistry tar imot det Load ga. client skal komme fra NewHTTPClient med
// samme allowInsecure, som her styrer hvilke endepunkt-URL-er som godtas.
func NewRegistry(providers map[string]Provider, byService map[string][]string, client *http.Client, allowInsecure bool) *Registry {
	r := &Registry{
		providers:     providers,
		byService:     byService,
		client:        client,
		allowInsecure: allowInsecure,
		entries:       make(map[string]*entry, len(providers)),
		now:           time.Now,
		timeout:       discoveryTimeout,
	}
	r.discoverFn = r.discover
	for slug := range providers {
		r.entries[slug] = &entry{}
	}
	return r
}

// Client er den vaktede klienten.
func (r *Registry) Client() *http.Client { return r.client }

// HTTPContext legger idp-klienten i både oauth2- og go-oidc-konteksten, så
// ingen kall mot leverandøren går utenom vakten.
func (r *Registry) HTTPContext(ctx context.Context) context.Context {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, r.client)
	return oidc.ClientContext(ctx, r.client)
}

// Exchange bytter kode mot token via idp-klienten.
func (r *Registry) Exchange(ctx context.Context, slug string, cfg *oauth2.Config, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	if _, ok := r.providers[slug]; !ok {
		return nil, ErrUnknownProvider
	}
	return cfg.Exchange(r.HTTPContext(ctx), code, opts...)
}

func (r *Registry) Get(slug string) (Provider, bool) {
	p, ok := r.providers[slug]
	return p, ok
}

// ForService gir bare lastede leverandører, i tilordningsrekkefølge. En slug
// som ble avvist ved lasting eller ikke finnes gir ingen leverandør, selv om
// den står i byService.
func (r *Registry) ForService(serviceID string) []Provider {
	var out []Provider
	for _, slug := range r.byService[serviceID] {
		if p, ok := r.providers[slug]; ok {
			out = append(out, p)
		}
	}
	return out
}

// Discover returnerer cachet discovery for slug. Er verdien eldre enn 24 t,
// men yngre enn 7 døgn, returneres den straks mens fornyelsen kjører i
// bakgrunnen. Bare kall uten brukbar forrige verdi venter på hentingen, og
// da kan kalleren avbryte ventingen. Selve hentingen er løsrevet fra
// kallerens kontekst (go-oidc lagrer konteksten i nøkkelsettet).
func (r *Registry) Discover(ctx context.Context, slug string) (*Discovered, error) {
	p, ok := r.providers[slug]
	e := r.entries[slug]
	if !ok || e == nil {
		return nil, ErrUnknownProvider
	}
	e.mu.Lock()
	now := r.now()
	age := now.Sub(e.fetchedAt)
	if e.d != nil && age < discoveryTTL {
		d := e.d
		e.mu.Unlock()
		return d, nil
	}
	if e.d != nil && age < discoveryMaxAge {
		d := e.d
		if e.inflight == nil && !now.Before(e.retryAfter) {
			r.startLocked(p, e)
		}
		e.mu.Unlock()
		return d, nil
	}
	if e.inflight == nil {
		if now.Before(e.retryAfter) {
			err := e.lastErr
			e.mu.Unlock()
			return nil, err
		}
		r.startLocked(p, e)
	}
	f := e.inflight
	e.mu.Unlock()
	select {
	case <-f.done:
		return f.d, f.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (r *Registry) startLocked(p Provider, e *entry) {
	f := &flight{done: make(chan struct{})}
	e.inflight = f
	go r.fetch(p, e, f)
}

func (r *Registry) fetch(p Provider, e *entry, f *flight) {
	d, err := r.safeDiscover(p)
	e.mu.Lock()
	now := r.now()
	if err == nil {
		e.d, e.fetchedAt, e.lastErr, e.retryAfter = d, now, nil, time.Time{}
	} else {
		// Samme 60 s gjelder fornyelse som feiler, så en nedetid hos
		// leverandøren ikke gir en henting per innlogging.
		e.lastErr, e.retryAfter = err, now.Add(discoveryNegTTL)
		slog.Warn("idp: discovery feilet", "slug", p.Slug, "reason", DiscoveryReason(err), "stale", e.d != nil)
	}
	e.inflight = nil
	e.mu.Unlock()
	f.d, f.err = d, err
	close(f.done)
}

// safeDiscover gjør at en panikk i bakgrunnshentingen blir en feil, ikke en
// nedtatt prosess.
func (r *Registry) safeDiscover(p Provider) (d *Discovered, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			d, err = nil, discErr("fetch")
		}
	}()
	return r.discoverFn(p)
}

type discoveryDoc struct {
	AuthURL    string    `json:"authorization_endpoint"`
	TokenURL   string    `json:"token_endpoint"`
	JWKSURL    string    `json:"jwks_uri"`
	Algs       *[]string `json:"id_token_signing_alg_values_supported"`
	AuthMethod []string  `json:"token_endpoint_auth_methods_supported"`
}

func (r *Registry) discover(p Provider) (*Discovered, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	prov, err := oidc.NewProvider(oidc.ClientContext(ctx, r.client), p.Issuer)
	if err != nil {
		return nil, classified(err)
	}
	var doc discoveryDoc
	if err := prov.Claims(&doc); err != nil {
		return nil, discErr("fetch")
	}
	for _, u := range []string{doc.AuthURL, doc.TokenURL, doc.JWKSURL} {
		if !r.endpointOK(u) {
			return nil, discErr("endpoint_scheme")
		}
	}
	algs, err := intersectAlgs(doc.Algs)
	if err != nil {
		return nil, err
	}
	style, err := authStyle(p, doc.AuthMethod)
	if err != nil {
		return nil, err
	}
	ep := prov.Endpoint()
	ep.AuthStyle = style
	return &Discovered{Provider: prov, Endpoint: ep, Algs: algs}, nil
}

// classified klassifiserer rå feil til en DiscoveryError uten feilteksten.
func classified(err error) error {
	reason := DiscoveryReason(err)
	return discErr(reason)
}

// endpointOK krever https, eller http mot loopback når usikker modus er på.
func (r *Registry) endpointOK(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" || !r.allowInsecure {
		return false
	}
	h := strings.ToLower(u.Hostname())
	if h == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.Unmap().IsLoopback()
}

// intersectAlgs: manglende felt gir RS256 (OIDC Discovery §3), og tomt snitt
// er en feil, ikke en stille fallback.
func intersectAlgs(listed *[]string) ([]string, error) {
	if listed == nil {
		return []string{"RS256"}, nil
	}
	var out []string
	for _, a := range *listed {
		if allowedAlgs[a] {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, discErr("no_algs")
	}
	return out, nil
}

// authStyle foretrekker Basic. Offentlig klient sender bare client_id i
// kroppen. Uten annonserte metoder gjelder standarden client_secret_basic.
func authStyle(p Provider, methods []string) (oauth2.AuthStyle, error) {
	if p.ClientSecret == "" {
		return oauth2.AuthStyleInParams, nil
	}
	if methods == nil {
		return oauth2.AuthStyleInHeader, nil
	}
	post := false
	for _, m := range methods {
		switch m {
		case "client_secret_basic":
			return oauth2.AuthStyleInHeader, nil
		case "client_secret_post":
			post = true
		}
	}
	if post {
		return oauth2.AuthStyleInParams, nil
	}
	return 0, discErr("auth_method")
}
