package auth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	googleOAuth2 "golang.org/x/oauth2/google"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

type GoogleHandlers struct {
	cfg           config.Config
	sqlDB         *sql.DB
	reg           *service.Registry
	aud           *audit.Service
	adminSessions AdminSessionStarter
	resolver      *identityResolver
	fed           *federatedLogin
	// endpoint overstyres bare i tester, så kodeutveksling ikke treffer Google.
	endpoint *oauth2.Endpoint
	// fetchClaims er en testsøm; nil betyr ekte kodeutveksling og verifisering.
	fetchClaims func(ctx context.Context, cfg *oauth2.Config, clientID, code string) (cl googleClaims, tokenNonce, reason string)
}

func NewGoogleHandlers(cfg config.Config, sqlDB *sql.DB, q *gen.Queries, iss *token.Issuer, ref *token.RefreshService, reg *service.Registry, aud *audit.Service, adminSessions AdminSessionStarter) *GoogleHandlers {
	resolver := newIdentityResolver(sqlDB, aud)
	completer := &loginCompleter{queries: q, issuer: iss, refresh: ref, aud: aud}
	return &GoogleHandlers{cfg: cfg, sqlDB: sqlDB, reg: reg, aud: aud, adminSessions: adminSessions, resolver: resolver,
		fed: &federatedLogin{resolver: resolver, completer: completer, aud: aud}}
}

// InitiateLogin — GET /oidc-login eller /social-login
// Hvis redirect_uri-param er satt, lagres den som cookie slik at /dispatch
// kan rute brukeren tilbake til riktig intern path etter callback.
func (h *GoogleHandlers) InitiateLogin(w http.ResponseWriter, r *http.Request) {
	// Lagre redirect_uri-cookie FØR Google-redirect (Java-mønster)
	if ru := r.URL.Query().Get("redirect_uri"); ru != "" {
		secure := os.Getenv("KAUTH_INSECURE_COOKIES") != "true"
		http.SetCookie(w, &http.Cookie{
			Name:     "redirect_uri",
			Value:    url.QueryEscape(ru),
			Path:     "/",
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   600,
		})
	}

	svc := resolveSocialService(h.reg, r)
	h.redirectToGoogle(w, r, svc, false)
}

// InitiateAdminLogin — GET /admin/google-init
// Starter samme Google-flyt og samme /callback som vanlig innlogging, men med
// admin-formål i den HMAC-signerte staten. Formålet hentes aldri fra query,
// cookie eller redirect_uri, og redirect_uri-cookien settes ikke: admin-flyten
// skal ikke innom /dispatch.
func (h *GoogleHandlers) InitiateAdminLogin(w http.ResponseWriter, r *http.Request) {
	svc := h.reg.ResolveOrDefault(r.Host, "", "")
	h.redirectToGoogle(w, r, svc, true)
}

func (h *GoogleHandlers) redirectToGoogle(w http.ResponseWriter, r *http.Request, svc *gen.Service, adminPurpose bool) {
	if svc.AuthGoogle != 1 {
		http.Error(w, "Google-innlogging ikke aktivert", http.StatusForbidden)
		return
	}
	clientID, _ := googleCreds(h.cfg, svc)
	nonce, err := generateNonce()
	if err != nil {
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}
	var state string
	if adminPurpose {
		state = signAdminState(h.cfg.OIDCStateSecret, svc.ID, nonce)
	} else {
		state = SignState(h.cfg.OIDCStateSecret, svc.ID, nonce)
	}
	oauthCfg := &oauth2.Config{
		ClientID:    clientID,
		Endpoint:    googleOAuth2.Endpoint,
		RedirectURL: "https://" + r.Host + "/callback",
		Scopes:      []string{oidc.ScopeOpenID, "email", "profile"},
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   os.Getenv("KAUTH_INSECURE_COOKIES") != "true",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
	authURL := oauthCfg.AuthCodeURL(state, oauth2.SetAuthURLParam("prompt", "select_account"), oidc.Nonce(nonce))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleCallback — GET /callback
func (h *GoogleHandlers) HandleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// Admin-formålet leses bare fra den signerte staten, aldri fra query eller
	// andre cookies.
	claims, ok := readState(w, r, "oidc_state", h.cfg.OIDCStateSecret)
	if !ok {
		return
	}
	svcID, adminPurpose := claims.ServiceID, claims.Admin
	// Tjenesten kommer fra den signerte staten satt i InitiateLogin. Host-headeren
	// skal ikke kunne overstyre den, ellers ender en undertjeneste uten egen
	// auth_host (delt host) opp som foreldretjenesten.
	// En tjeneste som er deaktivert mens staten levde, avvises i stedet for å
	// falle til default-tjenesten med dens policy og callback.
	svc := h.reg.Resolve("", svcID, "")
	if svc == nil {
		h.rejectCallback(w, r, &gen.Service{ID: svcID}, adminPurpose, "unknown_service")
		return
	}
	clientID, clientSecret := googleCreds(h.cfg, svc)
	oauthCfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     h.tokenEndpoint(),
		RedirectURL:  "https://" + r.Host + "/callback",
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
	fetch := h.fetchClaims
	if fetch == nil {
		fetch = fetchGoogleClaims
	}
	cl, tokenNonce, reason := fetch(ctx, oauthCfg, clientID, r.URL.Query().Get("code"))
	if reason != "" {
		h.rejectCallback(w, r, svc, adminPurpose, reason)
		return
	}
	h.finishCallback(w, r, svc, adminPurpose, cl, tokenNonce, claims.Nonce)
}

// fetchGoogleClaims bytter koden, verifiserer id_token mot Googles discovery og
// leser claims. reason er tom ved suksess, ellers den tekniske årsaken som går
// til audit.
func fetchGoogleClaims(ctx context.Context, cfg *oauth2.Config, clientID, code string) (cl googleClaims, tokenNonce, reason string) {
	oauth2Token, err := cfg.Exchange(ctx, code)
	if err != nil {
		return cl, "", "code_exchange"
	}
	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		return cl, "", "discovery"
	}
	rawIDToken, _ := oauth2Token.Extra("id_token").(string)
	idToken, err := provider.Verifier(&oidc.Config{ClientID: clientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return cl, "", "id_token"
	}
	if err := idToken.Claims(&cl); err != nil {
		return googleClaims{}, "", "claims"
	}
	return cl, idToken.Nonce, ""
}

// rejectCallback avviser en callback med generisk respons. Teknisk årsak går til
// audit og logg, aldri til responsen. Admin-feil auditeres som mislykket
// admin-innlogging.
func (h *GoogleHandlers) rejectCallback(w http.ResponseWriter, r *http.Request, svc *gen.Service, adminPurpose bool, reason string) {
	slog.Debug("google: callback avvist", "reason", reason)
	if adminPurpose {
		h.auditAdminFailure(r, svc, "", "reason="+reason)
		redirectAdminLoginError(w, r)
		return
	}
	h.fed.reject(w, r, providerGoogle, svc, rejection{Reason: reason})
}

// checkIDTokenNonce sammenligner nonce i id_token med den i den signerte
// staten. Tom nonce på en av sidene avvises, ellers ville to tomme verdier
// passert.
func checkIDTokenNonce(tokenNonce, stateNonce string) bool {
	if tokenNonce == "" || stateNonce == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(tokenNonce), []byte(stateNonce)) == 1
}

func (h *GoogleHandlers) tokenEndpoint() oauth2.Endpoint {
	if h.endpoint != nil {
		return *h.endpoint
	}
	return googleOAuth2.Endpoint
}

// googleClaims er det vi trenger fra Googles id_token.
type googleClaims struct {
	Sub           string `json:"sub"`
	Iss           string `json:"iss"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	EmailVerified bool   `json:"email_verified"`
}

// googleIssuer er den kanoniske issuer-verdien lagret på identiteter (PD6).
const googleIssuer = "https://accounts.google.com"

// googleIdentity bygger identiteten fra verifiserte claims. Google sender iss
// både med og uten https://; begge normaliseres, så samme person aldri får to
// identiteter. ok=false betyr manglende sub eller fremmed issuer.
func googleIdentity(cl googleClaims, email string) (externalIdentity, bool) {
	if cl.Iss != googleIssuer && cl.Iss != "accounts.google.com" {
		return externalIdentity{}, false
	}
	if strings.TrimSpace(cl.Sub) == "" {
		return externalIdentity{}, false
	}
	return externalIdentity{Provider: "google", Issuer: googleIssuer, Subject: cl.Sub, Email: email, Name: cl.Name}, true
}

// finishCallback er alt som skjer etter at id_token er verifisert og claims er
// lest. Skilt ut fra HandleCallback slik at begge grenene kan testes uten
// Google. Nonce-sjekken ligger her så den dekkes av tester uten live IdP.
func (h *GoogleHandlers) finishCallback(w http.ResponseWriter, r *http.Request, svc *gen.Service, adminPurpose bool, cl googleClaims, tokenNonce, stateNonce string) {
	// Binder id_token til akkurat denne innloggingsøkten (replay av et token
	// fra en annen økt avvises). Først, så begge grener dekkes.
	if !checkIDTokenNonce(tokenNonce, stateNonce) {
		h.rejectCallback(w, r, svc, adminPurpose, "nonce")
		return
	}
	if adminPurpose {
		clearCookie(w, "oidc_state")
		h.completeAdminLogin(w, r, svc, cl)
		return
	}
	// Normalisert før alt annet, slik at oppslag, audit og lagring bruker samme
	// form uansett hvordan Google skriver adressen.
	email := NormalizeEmail(cl.Email)
	// Uverifisert e-post gir verken oppslag eller auto-registrering, ellers
	// kan en uverifisert adresse overta eller opprette en konto.
	if !cl.EmailVerified {
		h.fed.reject(w, r, providerGoogle, svc, rejection{Email: email, Reason: "email_unverified"})
		return
	}
	if email == "" {
		h.fed.reject(w, r, providerGoogle, svc, rejection{Email: email, Reason: "email_missing"})
		return
	}
	ext, ok := googleIdentity(cl, email)
	if !ok {
		h.fed.reject(w, r, providerGoogle, svc, rejection{Email: email, Reason: "missing_sub"})
		return
	}
	h.fed.finish(w, r, providerGoogle, svc, ext)
}

func googleCreds(cfg config.Config, svc *gen.Service) (id, secret string) {
	id = cfg.GoogleClientID
	if svc.GoogleClientID != nil && *svc.GoogleClientID != "" {
		id = *svc.GoogleClientID
	}
	secret = cfg.GoogleClientSecret
	if svc.GoogleClientSecret != nil && *svc.GoogleClientSecret != "" {
		secret = *svc.GoogleClientSecret
	}
	return
}
