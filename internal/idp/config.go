package idp

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/zral/kauth-go/internal/db/gen"
)

// Provider er en validert, lastet leverandør. ClientSecret er tom for
// offentlig klient.
type Provider struct {
	ID           int64
	Slug         string
	DisplayName  string
	Issuer       string
	ClientID     string
	ClientSecret string `json:"-"`
	Scopes       []string
	TrustEmail   bool
	EmailDomains []string
}

// String og GoString skjuler hemmeligheten, så en utilsiktet %v, %+v, %#v
// eller slog-attributt med hele Provider aldri lekker den.
func (p Provider) String() string {
	secret := ""
	if p.ClientSecret != "" {
		secret = "[skjult]"
	}
	return fmt.Sprintf("idp.Provider{slug=%s issuer=%s client_id=%s client_secret=%s trust_email=%t}",
		p.Slug, p.Issuer, p.ClientID, secret, p.TrustEmail)
}

func (p Provider) GoString() string { return p.String() }

// Options styrer validering. Getenv er injiserbar så tester slipper å røre
// prosessmiljøet.
type Options struct {
	Allowlist     []string
	AllowInsecure bool
	Getenv        func(string) string
}

// getenv faller tilbake til prosessmiljøet når ingen er injisert.
func (o Options) getenv() func(string) string {
	if o.Getenv == nil {
		return os.Getenv
	}
	return o.Getenv
}

var (
	slugRe      = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	secretEnvRe = regexp.MustCompile(`^KAUTH_IDP_[A-Z0-9_]+$`)
)

var reservedHosts = map[string]bool{
	"accounts.google.com":       true,
	"login.microsoftonline.com": true,
	"sts.windows.net":           true,
	"login.live.com":            true,
	"login.windows.net":         true,
	"login.microsoft.com":       true,
}

// isReserved slår opp vertsnavnet etter normalisering (små bokstaver, uten
// avsluttende '/' og '.'), så «HTTPS://accounts.google.com./» ikke slipper
// forbi en streng-likhet. Google og Microsoft har egne flyter med egne
// issuer-regler.
func isReserved(issuer string) bool {
	n := strings.ToLower(strings.TrimSpace(issuer))
	n = strings.TrimPrefix(strings.TrimPrefix(n, "https://"), "http://")
	n = strings.TrimRight(n, "/")
	host := n
	if u, err := url.Parse("https://" + n); err == nil {
		host = u.Hostname()
	} else if i := strings.IndexAny(n, "/?#"); i >= 0 {
		host = n[:i]
	}
	return reservedHosts[strings.TrimRight(host, ".")]
}

func inAllowlist(list []string, issuer string) bool {
	for _, a := range list {
		if a == issuer {
			return true
		}
	}
	return false
}

func validIssuerURL(issuer string, allowInsecure bool) bool {
	u, err := url.Parse(issuer)
	if err != nil || u.Opaque != "" || u.Hostname() == "" {
		return false
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(issuer, "#") {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && allowInsecure)
}

func splitList(s, sep string) []string {
	var out []string
	for _, f := range strings.Split(s, sep) {
		if f = strings.ToLower(strings.TrimSpace(f)); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// Input er allerede i små bokstaver. Streng hostname-form: ingen @, mellomrom,
// sti, port eller wildcard kan snike seg inn i domenesammenligningen.
var domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

func validDomain(d string) bool { return domainRe.MatchString(d) }

const maxDisplayNameRunes = 64

// logSlug avkorter slug til 64 byte (på rune-grense) slik at en ugyldig,
// vilkårlig lang verdi fra DB ikke blåser opp loggen.
func logSlug(s string) string {
	if len(s) <= 64 {
		return s
	}
	s = s[:64]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// validate returnerer reason ved avvisning. Rekkefølgen er stabil, så hver
// regel har en egen reason i loggen.
func validate(row gen.IdentityProvider, opts Options) (Provider, string, bool) {
	getenv := opts.getenv()
	if row.Active != 1 {
		return Provider{}, "inactive", false
	}
	if !slugRe.MatchString(row.Slug) {
		return Provider{}, "bad_slug", false
	}
	name := strings.TrimSpace(row.DisplayName)
	if name == "" {
		return Provider{}, "display_name_empty", false
	}
	if utf8.RuneCountInString(name) > maxDisplayNameRunes {
		return Provider{}, "display_name_too_long", false
	}
	if !inAllowlist(opts.Allowlist, row.Issuer) {
		return Provider{}, "issuer_not_allowlisted", false
	}
	if isReserved(row.Issuer) {
		return Provider{}, "issuer_reserved", false
	}
	if !validIssuerURL(row.Issuer, opts.AllowInsecure) {
		return Provider{}, "issuer_invalid", false
	}
	var secret string
	if row.ClientSecretEnv != nil {
		name := *row.ClientSecretEnv
		if !secretEnvRe.MatchString(name) {
			return Provider{}, "secret_env_name", false
		}
		secret = getenv(name)
		if strings.TrimSpace(secret) == "" {
			return Provider{}, "secret_env_empty", false
		}
	}
	scopes := strings.Fields(row.Scopes)
	hasOpenID := false
	for _, s := range scopes {
		if s == "openid" {
			hasOpenID = true
		}
	}
	if !hasOpenID {
		return Provider{}, "scope_openid_missing", false
	}
	domains := splitList(row.EmailDomains, ",")
	for _, d := range domains {
		if !validDomain(d) {
			return Provider{}, "bad_email_domain", false
		}
	}
	if row.TrustEmail == 1 && len(domains) == 0 {
		return Provider{}, "trust_email_without_domains", false
	}
	return Provider{
		ID: row.ID, Slug: row.Slug, DisplayName: row.DisplayName, Issuer: row.Issuer,
		ClientID: row.ClientID, ClientSecret: secret, Scopes: scopes,
		TrustEmail: row.TrustEmail == 1, EmailDomains: domains,
	}, "", true
}

// Status er adminvisningen av én rad, også inaktive og avviste. Feltene er
// med vilje uten hemmelighetens verdi: bare env-navnet og om den er satt, så
// ingen %+v eller mal kan lekke den.
type Status struct {
	ID           int64
	Slug         string
	DisplayName  string
	Issuer       string
	Active       bool
	Loaded       bool
	Reason       string
	Allowlisted  bool
	SecretEnv    string
	SecretSet    bool
	TrustEmail   bool
	EmailDomains []string
}

func buildStatus(row gen.IdentityProvider, opts Options, loaded bool, reason string) Status {
	getenv := opts.getenv()
	st := Status{
		ID: row.ID, Slug: row.Slug, DisplayName: row.DisplayName, Issuer: row.Issuer,
		Active: row.Active == 1, Loaded: loaded, Reason: reason,
		Allowlisted: inAllowlist(opts.Allowlist, row.Issuer),
		TrustEmail:  row.TrustEmail == 1, EmailDomains: splitList(row.EmailDomains, ","),
	}
	// Kun et gyldig env-navn slås opp; ellers kunne en vilkårlig verdi fra DB
	// lese en annen hemmelighet i prosessmiljøet.
	if row.ClientSecretEnv != nil {
		st.SecretEnv = *row.ClientSecretEnv
		if secretEnvRe.MatchString(st.SecretEnv) {
			st.SecretSet = strings.TrimSpace(getenv(st.SecretEnv)) != ""
		}
	}
	return st
}

// Load leser alle leverandører og tilordninger. En avvist rad logges og
// hoppes over: én feil rad skal ikke ta ned de andre tjenestene. byService
// bevarer rekkefølgen fra spørringen (position, slug) og inneholder bare
// slugs som faktisk er lastet. Statuslisten dekker alle rader, med samme
// reason som logges. Inaktive rader logges ikke (de er bevisst av).
func Load(ctx context.Context, q *gen.Queries, opts Options) (map[string]Provider, map[string][]string, []Status, error) {
	rows, err := q.ListAllIdentityProviders(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("idp: les leverandører: %w", err)
	}
	providers := map[string]Provider{}
	slugByID := map[int64]string{}
	statuses := make([]Status, 0, len(rows))
	for _, row := range rows {
		p, reason, ok := validate(row, opts)
		statuses = append(statuses, buildStatus(row, opts, ok, reason))
		if !ok {
			if reason != "inactive" {
				slog.Warn("idp: leverandør ikke lastet", "slug", logSlug(row.Slug), "reason", reason)
			}
			continue
		}
		providers[p.Slug] = p
		slugByID[p.ID] = p.Slug
	}
	assigns, err := q.ListServiceIdentityProviders(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("idp: les tilordninger: %w", err)
	}
	byService := buildAssignments(assigns, slugByID)
	return providers, byService, statuses, nil
}

func buildAssignments(assigns []gen.ServiceIdentityProvider, slugByID map[int64]string) map[string][]string {
	byService := map[string][]string{}
	for _, a := range assigns {
		slug, ok := slugByID[a.ProviderID]
		if !ok {
			slog.Warn("idp: tilordning til leverandør som ikke er lastet", "service", a.ServiceID, "provider_id", a.ProviderID)
			continue
		}
		byService[a.ServiceID] = append(byService[a.ServiceID], slug)
	}
	return byService
}
