package auth

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"golang.org/x/oauth2"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/idp"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

const idpStateCookie = "idp_state"

// maxSubjectLen er øvre grense for sub (OIDC Core §2). Lengre verdier avvises
// i stedet for å lagres.
const maxSubjectLen = 255

var (
	loginOIDC    = loginMethod{AuditType: "oidc_login", AuthMethod: "oidc", LogPrefix: "oidc", StateCookie: idpStateCookie}
	providerOIDC = federatedProvider{login: loginOIDC, rejectedType: "oidc_rejected"}
)

// GenericOIDCHandlers er innlogging mot konfigurerbare OIDC-leverandører
// (015). Generisk identitet går aldri gjennom admin-stiene.
type GenericOIDCHandlers struct {
	cfg  config.Config
	reg  *service.Registry
	idps *idp.Registry
	aud  *audit.Service
	fed  *federatedLogin
	// links tar koblingsgrenen i callbacken (016). nil gjør at en state med
	// link= avvises i stedet for å falle gjennom til vanlig innlogging.
	links *LinkHandlers
}

func NewGenericOIDCHandlers(cfg config.Config, sqlDB *sql.DB, q *gen.Queries, iss *token.Issuer, ref *token.RefreshService, reg *service.Registry, idps *idp.Registry, aud *audit.Service) *GenericOIDCHandlers {
	resolver := newIdentityResolver(sqlDB, aud)
	completer := &loginCompleter{queries: q, issuer: iss, refresh: ref, aud: aud}
	return &GenericOIDCHandlers{cfg: cfg, reg: reg, idps: idps, aud: aud,
		fed: &federatedLogin{resolver: resolver, completer: completer, aud: aud}}
}

// WithLinks kobler på koblingsgrenen i callbacken.
func (h *GenericOIDCHandlers) WithLinks(l *LinkHandlers) *GenericOIDCHandlers {
	h.links = l
	return h
}

// idpRedirectURL følger samme Host-regel som Google: https, unntatt med
// KAUTH_INSECURE_COOKIES (lokal utvikling og eval over http).
func idpRedirectURL(r *http.Request, slug string) string {
	scheme := "https"
	if os.Getenv("KAUTH_INSECURE_COOKIES") == "true" {
		scheme = "http"
	}
	return scheme + "://" + r.Host + "/idp/" + slug + "/callback"
}

func providerFor(idps *idp.Registry, serviceID, slug string) (idp.Provider, bool) {
	for _, p := range idps.ForService(serviceID) {
		if p.Slug == slug {
			return p, true
		}
	}
	return idp.Provider{}, false
}

func idpContext(slug string) string { return "provider=" + slug }

// HandleLogin — GET /idp/{slug}/login
func (h *GenericOIDCHandlers) HandleLogin(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	svc := resolveSocialService(h.reg, r)
	if svc == nil {
		redirectLoginError(w, r, "", errCodeLoginFailed)
		return
	}
	// Ukjent og ikke-tilordnet leverandør er ikke et sikkerhetssignal fra en
	// innlogget økt, bare en feil lenke: ingen audit.
	p, ok := providerFor(h.idps, svc.ID, slug)
	if !ok {
		redirectLoginError(w, r, svc.ID, errCodeLoginFailed)
		return
	}
	d, err := h.idps.Discover(r.Context(), slug)
	if err != nil {
		slog.Warn("oidc: discovery feilet", "provider", slug, "reason", idp.DiscoveryReason(err))
		h.fed.reject(w, r, providerOIDC, svc, rejection{Context: idpContext(slug), Reason: "discovery"})
		return
	}
	nonce, err := generateNonce()
	if err != nil {
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}
	state := signIDPState(h.cfg.OIDCStateSecret, svc.ID, nonce, slug)
	oauthCfg := &oauth2.Config{
		ClientID:    p.ClientID,
		Endpoint:    d.Endpoint,
		RedirectURL: idpRedirectURL(r, slug),
		Scopes:      p.Scopes,
	}
	// Settes først når tjeneste, tilordning og discovery er validert, så en
	// mislykket init ikke etterlater en cookie. Samme cookie som Google, slik
	// at /dispatch kan rute tilbake.
	if ru := r.URL.Query().Get("redirect_uri"); ru != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "redirect_uri",
			Value:    url.QueryEscape(ru),
			Path:     "/",
			HttpOnly: true,
			Secure:   os.Getenv("KAUTH_INSECURE_COOKIES") != "true",
			SameSite: http.SameSiteLaxMode,
			MaxAge:   600,
		})
	}
	http.SetCookie(w, &http.Cookie{
		Name:     idpStateCookie,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   os.Getenv("KAUTH_INSECURE_COOKIES") != "true",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
	authURL := oauthCfg.AuthCodeURL(state, oauth2.S256ChallengeOption(idp.PKCEVerifier(h.cfg.OIDCStateSecret, state)), oidc.Nonce(nonce))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// idTokenClaims er det vi leser fra et verifisert id_token. email_verified
// leses løst fordi enkelte leverandører sender strengen "true".
type idTokenClaims struct {
	Azp           string          `json:"azp"`
	Email         string          `json:"email"`
	EmailVerified json.RawMessage `json:"email_verified"`
	Name          string          `json:"name"`
}

// claimTrue tolker bool true og strengen "true"; alt annet er false.
func claimTrue(raw json.RawMessage) bool {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b
	}
	var s string
	return json.Unmarshal(raw, &s) == nil && s == "true"
}

// emailDomainAllowed sammenligner delen etter siste «@» eksakt mot listen,
// uten subdomener.
func emailDomainAllowed(email string, domains []string) bool {
	i := strings.LastIndex(email, "@")
	if i < 0 || i == len(email)-1 {
		return false
	}
	domain := strings.ToLower(email[i+1:])
	for _, d := range domains {
		if domain == strings.ToLower(d) {
			return true
		}
	}
	return false
}

// azpOK krever azp lik client_id når aud har flere verdier, og når azp er
// satt uansett (OIDC Core §3.1.3.7).
func azpOK(aud []string, azp, clientID string) bool {
	return !((len(aud) > 1 || azp != "") && azp != clientID)
}

// rawEmailSafe sier om den rå e-posten er ren ASCII med nøyaktig én «@».
// NormalizeEmail bretter Unicode (f.eks. Kelvin-tegnet U+212A til «k»), så en
// IdP-adresse som ser annerledes ut kunne ellers havne på en annen brukers
// normaliserte adresse. Tillit gis derfor bare for uforfalsket ASCII. Sjekken
// gjøres på den utrimmede verdien og avviser også mellomrom og kontrolltegn,
// fordi TrimSpace i NormalizeEmail ellers fjerner f.eks. U+00A0 i endene og
// gjør «kari@korp.no<NBSP>» til Karis adresse.
func rawEmailSafe(raw string) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] <= 0x20 || raw[i] >= 0x7f {
			return false
		}
	}
	return token.ValidEmail(raw)
}

// HandleCallback — GET /idp/{slug}/callback
func (h *GenericOIDCHandlers) HandleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pathSlug := chi.URLParam(r, "slug")
	claims, ok := readState(w, r, idpStateCookie, h.cfg.OIDCStateSecret)
	if !ok {
		return
	}
	// Cookien er engangsbruk uansett utfall.
	clearCookie(w, idpStateCookie)
	// Admin-state og state fra Google/MS (uten IDP) hører til andre flyter.
	if claims.IDP == "" || claims.Admin {
		redirectLoginError(w, r, "", errCodeLoginFailed)
		return
	}
	slug := claims.IDP
	// En koblingsflyt som avvises før grenen skal kunne spores til invitasjonen.
	rejectCtx := idpContext(slug)
	if claims.Link != 0 {
		rejectCtx += " invite=" + strconv.FormatInt(claims.Link, 10)
	}
	// Tjenesten og leverandøren kommer fra den signerte staten, aldri fra
	// Host eller stien.
	svc := h.reg.Resolve("", claims.ServiceID, "")
	if svc == nil {
		h.fed.auditRejected(r, providerOIDC, claims.ServiceID, rejection{Context: rejectCtx, Reason: "unknown_service"})
		redirectLoginError(w, r, "", errCodeLoginFailed)
		return
	}
	reject := func(reason string) {
		h.fed.reject(w, r, providerOIDC, svc, rejection{Context: rejectCtx, Reason: reason})
	}
	p, assigned := providerFor(h.idps, svc.ID, slug)
	if pathSlug != slug || !assigned {
		reject("unknown_provider")
		return
	}
	q := r.URL.Query()
	if q.Get("error") != "" {
		reject("provider_error")
		return
	}
	// RFC 9207: et iss-parameter må være utstederen vi sendte brukeren til.
	for _, iss := range q["iss"] {
		if iss != p.Issuer {
			reject("issuer_param")
			return
		}
	}
	d, err := h.idps.Discover(ctx, slug)
	if err != nil {
		slog.Warn("oidc: discovery feilet", "provider", slug, "reason", idp.DiscoveryReason(err))
		reject("discovery")
		return
	}
	// Annonserer leverandøren RFC 9207, er iss påkrevd: uten den kan et
	// mix-up-angrep ikke oppdages.
	var meta struct {
		IssParam bool `json:"authorization_response_iss_parameter_supported"`
	}
	// Kan ikke metadata leses, avvises innloggingen heller enn at kravet
	// stille hoppes over.
	if err := d.Provider.Claims(&meta); err != nil || (meta.IssParam && len(q["iss"]) == 0) {
		reject("issuer_param")
		return
	}
	oauthCfg := &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     d.Endpoint,
		RedirectURL:  idpRedirectURL(r, slug),
		Scopes:       p.Scopes,
	}
	// Staten er verifisert og lik cookien, så den kan avlede verifieren.
	verifier := idp.PKCEVerifier(h.cfg.OIDCStateSecret, q.Get("state"))
	tok, err := h.idps.Exchange(ctx, slug, oauthCfg, q.Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		// Feilteksten kan inneholde svarkroppen fra leverandøren og logges ikke.
		reject("code_exchange")
		return
	}
	rawIDToken, _ := tok.Extra("id_token").(string)
	if rawIDToken == "" {
		reject("id_token_missing")
		return
	}
	idt, err := d.Verifier(p.ClientID).Verify(h.idps.HTTPContext(ctx), rawIDToken)
	if err != nil {
		reject("id_token")
		return
	}
	var cl idTokenClaims
	if err := idt.Claims(&cl); err != nil {
		reject("id_token")
		return
	}
	// go-oidc sjekker ikke azp.
	if !azpOK(idt.Audience, cl.Azp, p.ClientID) {
		reject("id_token")
		return
	}
	if !checkIDTokenNonce(idt.Nonce, claims.Nonce) {
		reject("nonce")
		return
	}
	sub := idt.Subject
	if strings.TrimSpace(sub) == "" || len(sub) > maxSubjectLen {
		reject("missing_sub")
		return
	}
	// Koblingsflyt (016): først etter all verifisering over, og aldri via
	// finishWithPolicy. Ingen tokens, sesjon eller redirect_uri.
	if claims.Link != 0 {
		if h.links == nil {
			reject("link_unavailable")
			return
		}
		h.links.finishLink(w, r, svc, p, claims.Link, sub, cl.Email)
		return
	}
	email := NormalizeEmail(cl.Email)
	// Tillit til e-post er en egenskap ved leverandøren og tokenet sammen (PD7).
	trusted := p.TrustEmail && claimTrue(cl.EmailVerified) && rawEmailSafe(cl.Email) && emailDomainAllowed(email, p.EmailDomains)
	if p.TrustEmail && email == "" {
		h.fed.reject(w, r, providerOIDC, svc, rejection{Context: idpContext(slug), Reason: "email_missing"})
		return
	}
	ext := externalIdentity{Provider: "oidc", Issuer: p.Issuer, Subject: sub, Email: email, Name: cl.Name}
	pol := policyFor(svc)
	pol.EmailUntrusted = !trusted
	h.fed.finishWithPolicy(w, r, providerOIDC, svc, ext, pol, idpContext(slug))
}
