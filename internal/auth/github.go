package auth

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/oauth2"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/idp"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

const (
	githubStateCookie = "gh_state"
	// githubIssuer er kanonisk uavhengig av KAUTH_GITHUB_BASE_URL, slik at
	// identiteter ikke endrer nøkkel mellom eval-oppsett og prod.
	githubIssuer = "https://github.com"
	// maxDisplayNameLen er øvre grense for visningsnavn fra en ekstern leverandør.
	maxDisplayNameLen = 100
)

var (
	loginGitHub    = loginMethod{AuditType: "github_oauth_login", AuthMethod: "github", LogPrefix: "github", StateCookie: githubStateCookie}
	providerGitHub = federatedProvider{login: loginGitHub, rejectedType: "github_oauth_rejected"}
)

// ghIdentity er det callbacken trenger fra GitHub etter kodeutvekslingen.
// Email er tom når primæradressen ikke er betrodd.
type ghIdentity struct {
	Subject, Name, Email string
	EmailTrusted         bool
}

// GitHubHandlers er innlogging med GitHub (019). GitHub er OAuth 2.0 uten
// id_token, så identiteten hentes med access-token fra REST-API-et.
type GitHubHandlers struct {
	cfg    config.Config
	reg    *service.Registry
	aud    *audit.Service
	fed    *federatedLogin
	client *githubClient
	// fetchIdentity er en testsøm; nil betyr ekte kall mot GitHub.
	fetchIdentity func(ctx context.Context, clientID, clientSecret, code, redirectURI, verifier string) (ghIdentity, error)
	// getenv er en testsøm for klienthemmeligheter; nil betyr os.Getenv.
	getenv func(string) string
}

func NewGitHubHandlers(cfg config.Config, sqlDB *sql.DB, q *gen.Queries, iss *token.Issuer, ref *token.RefreshService, reg *service.Registry, aud *audit.Service) *GitHubHandlers {
	resolver := newIdentityResolver(sqlDB, aud)
	completer := &loginCompleter{queries: q, issuer: iss, refresh: ref, aud: aud}
	return &GitHubHandlers{cfg: cfg, reg: reg, aud: aud,
		fed:    &federatedLogin{resolver: resolver, completer: completer, aud: aud},
		client: &githubClient{http: idp.NewHTTPClient(cfg.OIDCAllowInsecure), baseURL: cfg.GitHubBaseURL, apiURL: cfg.GitHubAPIURL}}
}

// githubRedirectURL bruker alltid https, også i insecure-modus: samme regel
// som Microsoft-flyten, og testleverandøren sjekker bare at verdien er lik i
// begge steg.
func githubRedirectURL(r *http.Request) string {
	return "https://" + r.Host + "/github-callback"
}

func (h *GitHubHandlers) clientID(svc *gen.Service) string {
	if svc.GithubClientID != nil && *svc.GithubClientID != "" {
		return *svc.GithubClientID
	}
	return h.cfg.GitHubClientID
}

// clientSecret feiler også når hemmeligheten er tom: GitHub har ingen
// klartekstkolonne, og en tom global verdi er en feilkonfigurasjon, ikke en
// klient uten hemmelighet.
func (h *GitHubHandlers) clientSecret(svc *gen.Service) (string, error) {
	s, err := resolveClientSecret(h.getenv, svc, "github", svc.GithubClientSecretEnv, nil, h.cfg.GitHubClientSecret)
	if err == nil && strings.TrimSpace(s) == "" {
		warnSecretMissing(svc.ID, "github", "KAUTH_GITHUB_CLIENT_SECRET")
		return "", errClientSecretMissing
	}
	return s, err
}

// InitiateLogin — GET /github-login
func (h *GitHubHandlers) InitiateLogin(w http.ResponseWriter, r *http.Request) {
	svc := resolveSocialService(h.reg, r)
	if svc == nil {
		redirectLoginError(w, r, "", errCodeLoginFailed)
		return
	}
	if svc.AuthGithub != 1 {
		http.Error(w, "GitHub-innlogging ikke aktivert", http.StatusForbidden)
		return
	}
	// Tom hemmelighet avvises ved start så brukeren ikke sendes til GitHub for å feile etterpå.
	if _, err := h.clientSecret(svc); err != nil {
		h.fed.reject(w, r, providerGitHub, svc, rejection{Reason: "client_secret_missing"})
		return
	}
	nonce, err := generateNonce()
	if err != nil {
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}
	state := signGitHubState(h.cfg.OIDCStateSecret, svc.ID, nonce)
	q := url.Values{
		"client_id":             {h.clientID(svc)},
		"response_type":         {"code"},
		"redirect_uri":          {githubRedirectURL(r)},
		"scope":                 {"read:user user:email"},
		"state":                 {state},
		"code_challenge":        {oauth2.S256ChallengeFromVerifier(idp.PKCEVerifier(h.cfg.OIDCStateSecret, state))},
		"code_challenge_method": {"S256"},
		"prompt":                {"select_account"},
	}
	http.SetCookie(w, &http.Cookie{
		Name:     githubStateCookie,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   os.Getenv("KAUTH_INSECURE_COOKIES") != "true",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
	// Svaret bærer en fersk state-cookie; et mellomlager må aldri gi den til en annen.
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, h.cfg.GitHubBaseURL+"/login/oauth/authorize?"+q.Encode(), http.StatusFound)
}

// HandleCallback — GET /github-callback. Rekkefølgen er en kontrakt (PD6).
func (h *GitHubHandlers) HandleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := readState(w, r, githubStateCookie, h.cfg.OIDCStateSecret)
	if !ok {
		return
	}
	// Cookien er engangsbruk uansett utfall.
	clearCookie(w, githubStateCookie)
	if !claims.GitHub {
		redirectLoginError(w, r, "", errCodeLoginFailed)
		return
	}
	// Tjenesten kommer fra den signerte staten, aldri fra Host.
	svc := h.reg.Resolve("", claims.ServiceID, "")
	if svc == nil {
		h.fed.auditRejected(r, providerGitHub, claims.ServiceID, rejection{Reason: "unknown_service"})
		redirectLoginError(w, r, "", errCodeLoginFailed)
		return
	}
	// Metoden kan være slått av etter at innloggingen startet.
	if svc.AuthGithub != 1 {
		h.fed.reject(w, r, providerGitHub, svc, rejection{Reason: "method_disabled"})
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		h.fed.reject(w, r, providerGitHub, svc, rejection{Context: "error=" + providerErrorToken(e), Reason: "provider_error"})
		return
	}
	secret, err := h.clientSecret(svc)
	if err != nil {
		h.fed.reject(w, r, providerGitHub, svc, rejection{Reason: "client_secret_missing"})
		return
	}
	fetch := h.fetchIdentity
	if fetch == nil {
		fetch = h.fetch
	}
	// Staten er verifisert og lik cookien, så den kan avlede verifieren.
	gi, err := fetch(ctx, h.clientID(svc), secret, q.Get("code"), githubRedirectURL(r), idp.PKCEVerifier(h.cfg.OIDCStateSecret, q.Get("state")))
	if err != nil {
		reason := "user_fetch"
		switch {
		case errors.Is(err, errGHCodeExchange):
			reason = "code_exchange"
		case errors.Is(err, errGHMissingID):
			reason = "missing_id"
		}
		h.fed.reject(w, r, providerGitHub, svc, rejection{Reason: reason})
		return
	}
	ext := externalIdentity{Provider: "github", Issuer: githubIssuer, Subject: gi.Subject, Email: gi.Email, Name: cleanDisplayName(gi.Name)}
	pol := policyFor(svc)
	pol.EmailUntrusted = !gi.EmailTrusted
	h.fed.finishWithPolicy(w, r, providerGitHub, svc, ext, pol, "")
}

// fetch er den ekte søm-implementasjonen: kodeutveksling, bruker, e-poster.
func (h *GitHubHandlers) fetch(ctx context.Context, clientID, secret, code, redirectURI, verifier string) (ghIdentity, error) {
	at, err := h.client.exchange(ctx, clientID, secret, code, redirectURI, verifier)
	if err != nil {
		return ghIdentity{}, err
	}
	u, err := h.client.user(ctx, at)
	if err != nil {
		return ghIdentity{}, err
	}
	sub, err := u.subject()
	if err != nil {
		return ghIdentity{}, err
	}
	list, err := h.client.emails(ctx, at)
	if err != nil {
		return ghIdentity{}, err
	}
	email, trusted := pickEmail(list)
	return ghIdentity{Subject: sub, Name: u.Name, Email: email, EmailTrusted: trusted}, nil
}

// providerErrorToken gjør error= fra leverandøren til en trygg Details-verdi:
// OAuth-feilkoder er ASCII-tokens, og alt annet (mellomrom, «reason=») kunne
// ellers forfalske felt i audit-raden. Maks 64 tegn.
func providerErrorToken(s string) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < 64; i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' {
			b.WriteByte(c)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// cleanDisplayName fjerner kontroll- og retningstegn og kutter på tegngrense,
// siden navnet er ekstern tekst som lagres i users.name og vises i admin.
// Retningstegn (bidi) kan snu visningen av omkringliggende tekst i admin.
func cleanDisplayName(s string) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || isBidiControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > maxDisplayNameLen {
		s = string([]rune(s)[:maxDisplayNameLen])
	}
	return strings.TrimSpace(s)
}

func isBidiControl(r rune) bool {
	return (r >= 0x200E && r <= 0x200F) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}
