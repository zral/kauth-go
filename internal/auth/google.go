package auth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	googleOAuth2 "golang.org/x/oauth2/google"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

// AdminSessionStarter lar OIDC-callbacken starte en admin-sesjon uten at auth
// kjenner admin-cookie, TTL eller admin-audit. Implementasjonen ligger i
// internal/admin (som ikke kan importeres herfra uten syklus) og injiseres fra
// main.go. Kalleren har allerede verifisert at brukeren er aktiv og har
// rollen konge.
type AdminSessionStarter interface {
	StartAdminSession(w http.ResponseWriter, r *http.Request, user gen.User, serviceID string) error
}

type GoogleHandlers struct {
	cfg           config.Config
	sqlDB         *sql.DB
	reg           *service.Registry
	aud           *audit.Service
	adminSessions AdminSessionStarter
	resolver      *identityResolver
	completer     *loginCompleter
	// endpoint overstyres bare i tester, så kodeutveksling ikke treffer Google.
	endpoint *oauth2.Endpoint
	// fetchClaims er en testsøm; nil betyr ekte kodeutveksling og verifisering.
	fetchClaims func(ctx context.Context, cfg *oauth2.Config, clientID, code string) (cl googleClaims, tokenNonce, reason string)
}

func NewGoogleHandlers(cfg config.Config, sqlDB *sql.DB, q *gen.Queries, iss *token.Issuer, ref *token.RefreshService, reg *service.Registry, aud *audit.Service, adminSessions AdminSessionStarter) *GoogleHandlers {
	return &GoogleHandlers{cfg: cfg, sqlDB: sqlDB, reg: reg, aud: aud, adminSessions: adminSessions, resolver: newIdentityResolver(sqlDB, aud), completer: &loginCompleter{queries: q, issuer: iss, refresh: ref, aud: aud}}
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
	sc, err := r.Cookie("oidc_state")
	if err != nil || sc.Value != r.URL.Query().Get("state") {
		redirectLoginError(w, r, "", errCodeLoginFailed)
		return
	}
	// Admin-formålet leses bare fra den signerte staten, aldri fra query eller
	// andre cookies.
	claims, ok := parseState(h.cfg.OIDCStateSecret, sc.Value)
	if !ok {
		redirectLoginError(w, r, "", errCodeLoginFailed)
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
	h.auditRejected(r, svc, "", "reason="+reason)
	redirectLoginError(w, r, svc.ID, errCodeLoginFailed)
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

// auditRejected skriver google_oidc_rejected for vanlig gren.
func (h *GoogleHandlers) auditRejected(r *http.Request, svc *gen.Service, email, reason string) {
	h.aud.Log(r.Context(), audit.Event{Type: "google_oidc_rejected", AuthMethod: "google", Email: email, ServiceID: svc.ID, IP: ClientIP(r), UA: r.Header.Get("User-Agent"), Success: false, Details: reason})
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
	ctx := r.Context()
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
		h.auditRejected(r, svc, email, "reason=email_unverified")
		redirectLoginError(w, r, svc.ID, errCodeLoginFailed)
		return
	}
	if email == "" {
		h.auditRejected(r, svc, email, "reason=email_missing")
		redirectLoginError(w, r, svc.ID, errCodeLoginFailed)
		return
	}
	ext, ok := googleIdentity(cl, email)
	if !ok {
		h.auditRejected(r, svc, email, "reason=missing_sub")
		redirectLoginError(w, r, svc.ID, errCodeLoginFailed)
		return
	}
	user, _, err := h.resolver.resolve(ctx, ext, policyFor(svc), resolveMeta{ServiceID: svc.ID, IP: ClientIP(r), UA: r.Header.Get("User-Agent")})
	if err != nil {
		switch {
		case errors.Is(err, errNoAccount):
			redirectLoginError(w, r, svc.ID, errCodeAccessDenied)
		case errors.Is(err, errUserInactive):
			h.auditRejected(r, svc, email, "reason=user_inactive")
			redirectLoginError(w, r, svc.ID, errCodeAccessDenied)
		case errors.Is(err, errLinkDenied):
			redirectLoginError(w, r, svc.ID, errCodeAccountNotLinked)
		case errors.Is(err, errUserConflict):
			slog.Warn("google: auto-registrering kolliderte med eksisterende rad", "service", svc.ID, "error", err)
			h.auditRejected(r, svc, email, "reason=user_conflict")
			redirectLoginError(w, r, svc.ID, errCodeLoginFailed)
		default:
			slog.Error("google: kunne ikke finne eller opprette bruker", "error", err)
			redirectLoginError(w, r, svc.ID, errCodeLoginFailed)
		}
		return
	}
	if err := h.completer.complete(w, r, svc, user, loginGoogle); err != nil {
		if errors.Is(err, errPolicyDenied) {
			redirectLoginError(w, r, svc.ID, errCodeAccessDenied)
		} else {
			redirectLoginError(w, r, svc.ID, errCodeLoginFailed)
		}
	}
}

// auditAdminFailure skriver admin_google_login med success=0.
func (h *GoogleHandlers) auditAdminFailure(r *http.Request, svc *gen.Service, email, details string) {
	h.aud.Log(r.Context(), audit.Event{Type: "admin_google_login", AuthMethod: "google", Email: email, ServiceID: svc.ID, IP: ClientIP(r), UA: r.Header.Get("User-Agent"), Success: false, Details: details})
}

// errAdminBindRollback ruller tilbake binding når identiteten ikke lot seg godkjenne.
var errAdminBindRollback = errors.New("admin-binding rullet tilbake")

// completeAdminLogin avslutter en OIDC-flyt med admin-formål. Den slår bare opp
// en eksisterende aktiv bruker: ingen auto-registrering og ingen tjenestepolicy
// (admin er ikke bundet til en tjeneste). Rollen konge kreves med eksakt match,
// og Google må ha bekreftet e-postadressen. Ingen JWT havner i URL-en;
// sesjonen settes som cookie av AdminSessionStarter.
func (h *GoogleHandlers) completeAdminLogin(w http.ResponseWriter, r *http.Request, svc *gen.Service, cl googleClaims) {
	ctx := r.Context()
	reject := func(email, details string) {
		h.auditAdminFailure(r, svc, email, details)
		redirectAdminLoginError(w, r)
	}
	// Normalisert slik at oppslaget ikke avhenger av hvordan Google skriver adressen.
	email := NormalizeEmail(cl.Email)
	if email == "" {
		reject("", "mangler e-post i id_token")
		return
	}
	if !cl.EmailVerified {
		reject(email, "e-post ikke verifisert av Google")
		return
	}
	ext, ok := googleIdentity(cl, email)
	if !ok {
		reject(email, "mangler sub eller ugyldig issuer i id_token")
		return
	}
	// Ingen auto-kobling utover overgangen og ingen auto-registrering (PD8):
	// admin-tilgang skal ikke følge av at noen kontrollerer en adresse hos Google.
	user, idn, _, err := h.resolver.resolveIdentity(ctx, ext, linkPolicy{}, resolveMeta{ServiceID: svc.ID, IP: ClientIP(r), UA: r.Header.Get("User-Agent")})
	if err != nil {
		if !errors.Is(err, errNoAccount) && !errors.Is(err, errUserInactive) && !errors.Is(err, errLinkDenied) {
			slog.Error("google: admin-oppslag feilet", "error", err)
		}
		reject(email, "ukjent, deaktivert eller ikke koblet")
		return
	}
	if !csvHasExact(user.Roles, "konge") {
		reject(email, "mangler konge-rolle")
		return
	}
	// Koblinger er globale: en identitet koblet via en vanlig tjeneste er ikke
	// dermed godkjent for admin. Første admin-innlogging for en ubundet bruker
	// binder brukeren (BindAdmin, bare én gang) og godkjenner identiteten i samme
	// transaksjon. En bundet bruker uten godkjent identitet avvises: en frakoblet
	// admin-identitet skal ikke kunne erstattes av en ny ved neste innlogging.
	if idn.AdminOk != 1 {
		boundAt := time.Now().UTC().Format("2006-01-02T15:04:05Z")
		res, err := bindAdminIdentity(ctx, h.sqlDB, user.ID, idn.ID, boundAt)
		if err != nil {
			slog.Error("google: kunne ikke binde admin-identitet", "error", err)
			reject(email, "intern feil")
			return
		}
		if res != adminBound {
			reason := "not_admin_identity"
			if res == adminIdentityVanished {
				reason = "identity_vanished"
			}
			h.aud.Log(context.WithoutCancel(ctx), audit.Event{Type: "identity_link_denied", AuthMethod: "google", Email: user.Email, ServiceID: svc.ID, IP: ClientIP(r), UA: r.Header.Get("User-Agent"), Success: false, Details: "reason=" + reason})
			reject(email, "identitet ikke godkjent for admin")
			return
		}
		h.aud.Log(context.WithoutCancel(ctx), audit.Event{Type: "identity_admin_approved", AuthMethod: "google", Email: user.Email, ServiceID: svc.ID, IP: ClientIP(r), UA: r.Header.Get("User-Agent"), Success: true, Details: "provider=" + ext.Provider + " issuer=" + ext.Issuer + " bound=1"})
	}
	if h.adminSessions == nil {
		slog.Error("google: admin-flyt uten AdminSessionStarter")
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}
	if err := h.adminSessions.StartAdminSession(w, r, user, svc.ID); err != nil {
		slog.Error("google: kunne ikke starte admin-sesjon", "email", user.Email, "error", err)
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
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

type adminBindResult int

const (
	adminBound            adminBindResult = iota
	adminAlreadyBound                     // brukeren er bundet fra før: ny identitet godkjennes ikke
	adminIdentityVanished                 // identiteten forsvant mellom oppslag og godkjenning
)

// bindAdminIdentity binder brukeren og godkjenner identiteten i én transaksjon.
// Mislykkes godkjenningen, rulles bindingen tilbake så brukeren ikke står bundet
// uten en godkjent identitet.
func bindAdminIdentity(ctx context.Context, sqlDB *sql.DB, userID, identityID int64, boundAt string) (adminBindResult, error) {
	res := adminAlreadyBound
	err := token.RunInTx(ctx, sqlDB, func(q *gen.Queries) error {
		n, err := q.BindAdmin(ctx, gen.BindAdminParams{AdminBoundAt: &boundAt, ID: userID})
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		n, err = q.SetAdminOK(ctx, gen.SetAdminOKParams{ID: identityID, UserID: userID, BoundAt: &boundAt})
		if err != nil {
			return err
		}
		if n == 0 {
			return errAdminBindRollback
		}
		res = adminBound
		return nil
	})
	if errors.Is(err, errAdminBindRollback) {
		return adminIdentityVanished, nil
	}
	return res, err
}
