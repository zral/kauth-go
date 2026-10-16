package idp

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
)

func strp(s string) *string { return &s }

func goodRow() gen.IdentityProvider {
	return gen.IdentityProvider{
		ID: 1, Slug: "acme", DisplayName: "Acme", Issuer: "https://idp.acme.example",
		ClientID: "cid", ClientSecretEnv: strp("KAUTH_IDP_ACME"),
		Scopes: "openid email profile", TrustEmail: 0, Active: 1,
	}
}

func optsFor(issuers ...string) Options {
	return Options{
		Allowlist: issuers,
		Getenv: func(k string) string {
			if k == "KAUTH_IDP_ACME" {
				return "s3cret"
			}
			return ""
		},
	}
}

func TestValidate_OK(t *testing.T) {
	p, reason, ok := validate(goodRow(), optsFor("https://idp.acme.example"))
	require.True(t, ok, reason)
	require.Equal(t, "s3cret", p.ClientSecret)
	require.Equal(t, []string{"openid", "email", "profile"}, p.Scopes)
}

func TestValidate_PublicClientAndDomains(t *testing.T) {
	r := goodRow()
	r.ClientSecretEnv = nil
	r.TrustEmail = 1
	r.EmailDomains = " Acme.Example, ,b.example "
	p, reason, ok := validate(r, optsFor(r.Issuer))
	require.True(t, ok, reason)
	require.Empty(t, p.ClientSecret)
	require.True(t, p.TrustEmail)
	require.Equal(t, []string{"acme.example", "b.example"}, p.EmailDomains)
}

func TestValidate_Rejections(t *testing.T) {
	cases := []struct {
		name   string
		mut    func(*gen.IdentityProvider)
		opts   func() Options
		reason string
	}{
		{"inaktiv", func(r *gen.IdentityProvider) { r.Active = 0 }, nil, "inactive"},
		{"slug store bokstaver", func(r *gen.IdentityProvider) { r.Slug = "Acme" }, nil, "bad_slug"},
		{"slug kolon", func(r *gen.IdentityProvider) { r.Slug = "a:b" }, nil, "bad_slug"},
		{"slug tom", func(r *gen.IdentityProvider) { r.Slug = "" }, nil, "bad_slug"},
		{"slug for lang", func(r *gen.IdentityProvider) { r.Slug = fmt.Sprintf("%033d", 0) }, nil, "bad_slug"},
		{"display_name tom", func(r *gen.IdentityProvider) { r.DisplayName = "  \t " }, nil, "display_name_empty"},
		{"display_name 65 runer", func(r *gen.IdentityProvider) { r.DisplayName = strings.Repeat("æ", 65) }, nil, "display_name_too_long"},
		{"ikke i allowlist", func(r *gen.IdentityProvider) { r.Issuer = "https://evil.example" }, nil, "issuer_not_allowlisted"},
		{"avsluttende slash", func(r *gen.IdentityProvider) { r.Issuer = "https://idp.acme.example/" }, nil, "issuer_not_allowlisted"},
		{"store bokstaver i issuer", func(r *gen.IdentityProvider) { r.Issuer = "https://IDP.acme.example" }, nil, "issuer_not_allowlisted"},
		{"port gir ikke treff", func(r *gen.IdentityProvider) { r.Issuer = "https://idp.acme.example:443" }, nil, "issuer_not_allowlisted"},
		{"@ gir ikke treff", func(r *gen.IdentityProvider) { r.Issuer = "https://idp.acme.example@evil.example" }, nil, "issuer_not_allowlisted"},
		{"http uten allowInsecure", func(r *gen.IdentityProvider) { r.Issuer = "http://idp.acme.example" }, allow("http://idp.acme.example"), "issuer_invalid"},
		{"query", func(r *gen.IdentityProvider) { r.Issuer = "https://idp.acme.example?x=1" }, allow("https://idp.acme.example?x=1"), "issuer_invalid"},
		{"tom query", func(r *gen.IdentityProvider) { r.Issuer = "https://idp.acme.example?" }, allow("https://idp.acme.example?"), "issuer_invalid"},
		{"fragment", func(r *gen.IdentityProvider) { r.Issuer = "https://idp.acme.example#f" }, allow("https://idp.acme.example#f"), "issuer_invalid"},
		{"userinfo", func(r *gen.IdentityProvider) { r.Issuer = "https://u:p@idp.acme.example" }, allow("https://u:p@idp.acme.example"), "issuer_invalid"},
		{"uten vert", func(r *gen.IdentityProvider) { r.Issuer = "https://" }, allow("https://"), "issuer_invalid"},
		{"annet skjema", func(r *gen.IdentityProvider) { r.Issuer = "ftp://idp.acme.example" }, allow("ftp://idp.acme.example"), "issuer_invalid"},
		{"hemmelighet: feil prefiks", func(r *gen.IdentityProvider) { r.ClientSecretEnv = strp("HOME") }, nil, "secret_env_name"},
		{"hemmelighet: state-secret", func(r *gen.IdentityProvider) { r.ClientSecretEnv = strp("KAUTH_OIDC_STATE_SECRET") }, nil, "secret_env_name"},
		{"hemmelighet: privat nokkel", func(r *gen.IdentityProvider) { r.ClientSecretEnv = strp("KAUTH_PRIVATE_KEY_PEM") }, nil, "secret_env_name"},
		{"hemmelighet: bare prefiks", func(r *gen.IdentityProvider) { r.ClientSecretEnv = strp("KAUTH_IDP_") }, nil, "secret_env_name"},
		{"hemmelighet: smaa bokstaver", func(r *gen.IdentityProvider) { r.ClientSecretEnv = strp("KAUTH_IDP_acme") }, nil, "secret_env_name"},
		{"hemmelighet: tom variabel", func(r *gen.IdentityProvider) { r.ClientSecretEnv = strp("KAUTH_IDP_MISSING") }, nil, "secret_env_empty"},
		{"hemmelighet: bare mellomrom", func(r *gen.IdentityProvider) { r.ClientSecretEnv = strp("KAUTH_IDP_BLANK") }, func() Options {
			o := optsFor("https://idp.acme.example")
			o.Getenv = func(string) string { return "  \t" }
			return o
		}, "secret_env_empty"},
		{"mangler openid", func(r *gen.IdentityProvider) { r.Scopes = "email profile" }, nil, "scope_openid_missing"},
		{"openid som delstreng", func(r *gen.IdentityProvider) { r.Scopes = "openidx email" }, nil, "scope_openid_missing"},
		{"trust uten domener", func(r *gen.IdentityProvider) { r.TrustEmail = 1; r.EmailDomains = " , " }, nil, "trust_email_without_domains"},
		{"domene med @", func(r *gen.IdentityProvider) { r.TrustEmail = 1; r.EmailDomains = "@acme.example" }, nil, "bad_email_domain"},
		{"domene uten punktum", func(r *gen.IdentityProvider) { r.TrustEmail = 1; r.EmailDomains = "localhost" }, nil, "bad_email_domain"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := goodRow()
			c.mut(&r)
			o := optsFor("https://idp.acme.example")
			if c.opts != nil {
				o = c.opts()
			}
			_, reason, ok := validate(r, o)
			require.False(t, ok)
			require.Equal(t, c.reason, reason)
		})
	}
}

func allow(issuer string) func() Options { return func() Options { return optsFor(issuer) } }

func TestValidate_Reserved(t *testing.T) {
	for _, iss := range []string{
		"https://accounts.google.com",
		"https://accounts.google.com/",
		"HTTPS://accounts.google.com",
		"accounts.google.com",
		"http://accounts.google.com",
		"https://login.microsoftonline.com/",
		"https://login.microsoftonline.com/common/v2.0",
		"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
		"https://sts.windows.net/abc/",
		"https://login.live.com",
		"https://login.live.com/x",
		"https://LOGIN.MICROSOFTONLINE.COM/t/v2.0",
		"https://accounts.google.com.",
		"https://accounts.google.com:443",
		"https://login.windows.net/t/",
		"login.windows.net",
		"https://login.microsoft.com/x",
	} {
		r := goodRow()
		r.Issuer = iss
		o := optsFor(iss)
		o.AllowInsecure = true
		_, reason, ok := validate(r, o)
		require.False(t, ok, iss)
		require.Equal(t, "issuer_reserved", reason, iss)
	}
}

func TestValidate_HTTPMedAllowInsecure(t *testing.T) {
	r := goodRow()
	r.Issuer = "http://127.0.0.1:8092"
	o := optsFor(r.Issuer)
	o.AllowInsecure = true
	_, reason, ok := validate(r, o)
	require.True(t, ok, reason)
}

func TestProvider_HemmelighetLekkerIkke(t *testing.T) {
	p := Provider{Slug: "acme", Issuer: "https://i.example", ClientID: "cid", ClientSecret: "TOPSECRET"}
	for _, s := range []string{
		fmt.Sprintf("%v", p), fmt.Sprintf("%+v", p), fmt.Sprintf("%#v", p), fmt.Sprint(p),
		fmt.Sprintf("%v", &p), fmt.Sprintf("%s", p),
	} {
		require.NotContains(t, s, "TOPSECRET")
	}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "p", p)
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "p", p)
	require.NotContains(t, buf.String(), "TOPSECRET")
}

func setup(t *testing.T) (*gen.Queries, func(string, ...any)) {
	t.Helper()
	d, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { d.Close() })
	return q, func(sql string, args ...any) {
		t.Helper()
		_, err := d.Exec(sql, args...)
		require.NoError(t, err)
	}
}

func TestLoad(t *testing.T) {
	q, ex := setup(t)
	ex(`INSERT INTO identity_providers (id,slug,display_name,issuer,client_id,client_secret_env) VALUES
		(1,'alfa','Alfa','https://a.example','ca','KAUTH_IDP_ALFA'),
		(2,'beta','Beta','https://b.example','cb',NULL),
		(3,'ute','Ute','https://ute.example','cu',NULL),
		(4,'uten-hemmelighet','X','https://c.example','cc','KAUTH_IDP_NONE')`)
	ex(`INSERT INTO identity_providers (id,slug,display_name,issuer,client_id,active) VALUES (5,'inaktiv','I','https://d.example','cd',0)`)
	for _, s := range []string{"s1", "s2", "s3"} {
		ex(`INSERT INTO services (id,display_name,domain,callback_url,email_from_name,updated_at,active) VALUES (?,?,?,?,'S','2026-01-01T00:00:00Z',1)`,
			s, s, s+".no", "https://"+s+".no/cb")
	}
	ex(`INSERT INTO service_identity_providers (service_id,provider_id,position) VALUES
		('s1',2,0),('s1',1,1),('s1',3,2),('s1',4,3),('s1',5,4),('s2',3,0),('s3',1,0)`)

	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(old)

	o := Options{
		Allowlist: []string{"https://a.example", "https://b.example", "https://c.example", "https://d.example"},
		Getenv: func(k string) string {
			if k == "KAUTH_IDP_ALFA" {
				return "hemmelig-verdi"
			}
			return ""
		},
	}
	providers, by, err := Load(context.Background(), q, o)
	require.NoError(t, err)
	require.Len(t, providers, 2)
	require.Equal(t, "hemmelig-verdi", providers["alfa"].ClientSecret)
	require.Empty(t, providers["beta"].ClientSecret)
	require.Equal(t, map[string][]string{"s1": {"beta", "alfa"}, "s3": {"alfa"}}, by)

	out := buf.String()
	require.Contains(t, out, "idp: leverandør ikke lastet")
	require.Contains(t, out, "slug=ute")
	require.Contains(t, out, "reason=issuer_not_allowlisted")
	require.Contains(t, out, "slug=uten-hemmelighet")
	require.Contains(t, out, "reason=secret_env_empty")
	require.NotContains(t, out, "hemmelig-verdi")
	require.Contains(t, out, "idp: tilordning til leverandør som ikke er lastet")
	require.Contains(t, out, "service=s2")
	require.Contains(t, out, "provider_id=3")
}

func TestLogSlug(t *testing.T) {
	require.Equal(t, "acme", logSlug("acme"))
	require.Len(t, logSlug(strings.Repeat("a", 500)), 64)
	require.True(t, utf8.ValidString(logSlug(strings.Repeat("æ", 100))))
}

func TestValidate_DisplayName64OK(t *testing.T) {
	r := goodRow()
	r.DisplayName = strings.Repeat("æ", 64)
	_, reason, ok := validate(r, optsFor("https://idp.acme.example"))
	require.True(t, ok, reason)
}

func TestValidate_TomAllowlist(t *testing.T) {
	_, reason, ok := validate(goodRow(), Options{})
	require.False(t, ok)
	require.Equal(t, "issuer_not_allowlisted", reason)
}

func TestValidDomain(t *testing.T) {
	for _, d := range []string{"contoso.com", "test.no", "example.test", "statnett.no", "a.b.example", "outlook.com"} {
		require.True(t, validDomain(d), d)
	}
	for _, d := range []string{"a@b.com", "a b.com", "a\tb.com", "a/b.com", "localhost", `a\b.com`,
		"*.example.com", "a..b.com", "example.com:443", "æøå.no", "-a.com", "", "a.c"} {
		require.False(t, validDomain(d), d)
	}
}
