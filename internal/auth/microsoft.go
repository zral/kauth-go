package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

// msAuthBase er base-URL for Microsoft /common v2.0-endepunktet.
// Nøkkel-URL blir msAuthBase+"/keys" = https://login.microsoftonline.com/common/oauth2/v2.0/keys.
// Microsoft publiserer faktisk nøkler på /discovery/v2.0/keys, men /v2.0/keys redirecter dit
// og fungerer i praksis. Dersom go-oidc klager på URL ved integrasjonstest kan dette endres.
const msAuthBase = "https://login.microsoftonline.com/common/oauth2/v2.0"

type MicrosoftHandlers struct {
	cfg      config.Config
	reg      *service.Registry
	aud      *audit.Service
	resolver *identityResolver
	fed      *federatedLogin
	// fetchClaims er en testsøm; nil betyr ekte kodeutveksling og verifisering.
	fetchClaims func(ctx context.Context, cfg *oauth2.Config, code string) (msClaims, error)
	// getenv er en testsøm for klienthemmeligheter; nil betyr os.Getenv.
	getenv func(string) string
}

func NewMicrosoftHandlers(cfg config.Config, sqlDB *sql.DB, q *gen.Queries, iss *token.Issuer, ref *token.RefreshService, reg *service.Registry, aud *audit.Service) *MicrosoftHandlers {
	resolver := newIdentityResolver(sqlDB, aud)
	completer := &loginCompleter{queries: q, issuer: iss, refresh: ref, aud: aud}
	return &MicrosoftHandlers{cfg: cfg, reg: reg, aud: aud, resolver: resolver,
		fed: &federatedLogin{resolver: resolver, completer: completer, aud: aud}}
}

// InitiateLogin — GET /ms-oidc-login
func (h *MicrosoftHandlers) InitiateLogin(w http.ResponseWriter, r *http.Request) {
	svc := resolveSocialService(h.reg, r)
	if svc.AuthMicrosoft != 1 {
		http.Error(w, "Microsoft-innlogging ikke aktivert", http.StatusForbidden)
		return
	}
	clientID := msCreds(h.cfg, svc)
	// Tom referanse betyr at metoden er ute for tjenesten (K13); avvis ved start
	// så brukeren ikke sendes til Microsoft for å feile etterpå.
	if _, err := h.clientSecret(svc); err != nil {
		h.fed.reject(w, r, providerMicrosoft, svc, rejection{Reason: "client_secret_missing"})
		return
	}
	// Fix 4: handle generateNonce error rather than silently ignoring it
	nonce, err := generateNonce()
	if err != nil {
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}
	state := SignState(h.cfg.OIDCStateSecret, svc.ID, nonce)
	oauthCfg := &oauth2.Config{
		ClientID:    clientID,
		RedirectURL: "https://" + r.Host + "/ms-callback",
		Scopes:      []string{"openid", "email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  msAuthBase + "/authorize",
			TokenURL: msAuthBase + "/token",
		},
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "ms_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   os.Getenv("KAUTH_INSECURE_COOKIES") != "true",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
	http.Redirect(w, r, oauthCfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.SetAuthURLParam("prompt", "select_account")), http.StatusFound)
}

// HandleCallback — GET /ms-callback
func (h *MicrosoftHandlers) HandleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := readState(w, r, "ms_state", h.cfg.OIDCStateSecret)
	if !ok {
		return
	}
	// Microsoft har ingen admin-flyt. En admin-, GitHub- eller IDP-state er signert for en
	// annen flyt og avvises før tjenesteoppslag og kodeutveksling.
	if claims.Admin || claims.IDP != "" || claims.GitHub {
		redirectLoginError(w, r, "", errCodeLoginFailed)
		return
	}
	// Tjenesten kommer fra den signerte staten satt i InitiateLogin, se google.go.
	svc := h.reg.Resolve("", claims.ServiceID, "")
	if svc == nil {
		h.fed.auditRejected(r, providerMicrosoft, claims.ServiceID, rejection{Reason: "unknown_service"})
		redirectLoginError(w, r, "", errCodeLoginFailed)
		return
	}
	clientID := msCreds(h.cfg, svc)
	clientSecret, err := h.clientSecret(svc)
	if err != nil {
		h.fed.reject(w, r, providerMicrosoft, svc, rejection{Reason: "client_secret_missing"})
		return
	}
	oauthCfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "https://" + r.Host + "/ms-callback",
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  msAuthBase + "/authorize",
			TokenURL: msAuthBase + "/token",
		},
	}
	fetch := h.fetchClaims
	if fetch == nil {
		fetch = fetchMSClaims
	}
	cl, err := fetch(ctx, oauthCfg, r.URL.Query().Get("code"))
	if err != nil {
		// Kodeutveksling og id_token-verifisering auditeres uten tid: ingen
		// claims er lest fra et verifisert token.
		switch {
		case errors.Is(err, errClaimsDecode):
			h.fed.auditRejected(r, providerMicrosoft, svc.ID, rejection{Context: msTidContext(cl.Tid), Reason: msReasonClaimsDecode})
		case errors.Is(err, errMSCodeExchange):
			slog.Warn("microsoft: kodeutveksling feilet", "service", svc.ID, "error", err)
			h.fed.auditRejected(r, providerMicrosoft, svc.ID, rejection{Reason: msReasonCodeExchange})
		case errors.Is(err, errMSIDToken):
			slog.Warn("microsoft: id_token ble ikke godkjent", "service", svc.ID, "error", err)
			h.fed.auditRejected(r, providerMicrosoft, svc.ID, rejection{Reason: msReasonIDToken})
		default:
			slog.Warn("microsoft: id_token-henting feilet", "error", err)
		}
		redirectLoginError(w, r, svc.ID, errCodeLoginFailed)
		return
	}
	h.finishCallback(w, r, svc, cl, claims.Nonce)
}

var errClaimsDecode = errors.New("claims kunne ikke dekodes")

// Sentinels for fetchMSClaims, så HandleCallback kan audite årsaken uten å
// sende IdP-tekst videre.
var (
	errMSCodeExchange = errors.New("kodeutveksling feilet")
	errMSIDToken      = errors.New("id_token ble ikke godkjent")
)

// msKeysURL er Microsofts JWKS-endepunkt. Variabelen er ueksportert og
// finnes bare så tester kan peke på en lokal server; prod-verdien er
// uendret. Tester som endrer den, kan ikke kjøres med t.Parallel.
var msKeysURL = "https://login.microsoftonline.com/common/discovery/v2.0/keys"

// fetchMSClaims bytter koden, verifiserer id_token-signaturen og dekoder claims.
// Ved dekodingsfeil returneres det som lot seg lese av tid sammen med errClaimsDecode.
func fetchMSClaims(ctx context.Context, cfg *oauth2.Config, code string) (msClaims, error) {
	oauth2Token, err := cfg.Exchange(ctx, code)
	if err != nil {
		return msClaims{}, fmt.Errorf("%w: %v", errMSCodeExchange, err)
	}
	rawIDToken, _ := oauth2Token.Extra("id_token").(string)
	// SkipIssuerCheck er nødvendig: /common utsteder per-tenant iss. Signatur,
	// audience og utløp verifiseres fortsatt; issuer sjekkes i validateMSClaims.
	verifier := oidc.NewVerifier(
		msAuthBase,
		oidc.NewRemoteKeySet(ctx, msKeysURL),
		&oidc.Config{ClientID: cfg.ClientID, SkipIssuerCheck: true},
	)
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return msClaims{}, fmt.Errorf("%w: %v", errMSIDToken, err)
	}
	var cl msClaims
	if err := idToken.Claims(&cl); err != nil {
		// Feilen fra JSON-dekoderen navngir felt og type, ikke verdier, og
		// trengs for å se hvilken claim Microsoft sender i et annet format.
		slog.Warn("microsoft: claims kunne ikke dekodes", "err", err)
		var partial struct {
			Tid string `json:"tid"`
		}
		_ = idToken.Claims(&partial)
		return msClaims{Tid: partial.Tid}, errClaimsDecode
	}
	cl.XmsEdov = parseEdov(cl.XmsEdovRaw)
	return cl, nil
}

// msTidContext er tenant-konteksten i audit-details ved avslag på claim-nivå.
// tid kommer fra IdP-en og renses som annen ekstern tekst i logg.
func msTidContext(tid string) string {
	if tid == "" {
		return ""
	}
	return "tid=" + sanitizeLogValue(tid)
}

// finishCallback tar over etter at id_token er signaturverifisert, slik at
// claims-avslag og policy kan testes uten nettverk.
func (h *MicrosoftHandlers) finishCallback(w http.ResponseWriter, r *http.Request, svc *gen.Service, cl msClaims, stateNonce string) {
	email, reason := validateMSClaims(cl, stateNonce)
	email = NormalizeEmail(email)
	if reason != "" {
		h.fed.reject(w, r, providerMicrosoft, svc, rejection{Context: msTidContext(cl.Tid), Reason: reason})
		return
	}
	// oid er subject (PD6). Uten gyldig oid finnes ingen stabil nøkkel, og
	// da faller vi ikke tilbake til e-post.
	if !msGUIDPattern.MatchString(cl.Oid) {
		h.fed.reject(w, r, providerMicrosoft, svc, rejection{Context: msTidContext(cl.Tid), Reason: msReasonMissingOID})
		return
	}
	ext := externalIdentity{Provider: "microsoft", Issuer: "https://login.microsoftonline.com/" + strings.ToLower(cl.Tid) + "/v2.0", Subject: strings.ToLower(cl.Oid), Email: email, Name: cl.Name}
	h.fed.finish(w, r, providerMicrosoft, svc, ext)
}

// msCreds gir klient-ID. Hemmeligheten går via clientSecret.
func msCreds(cfg config.Config, svc *gen.Service) (id string) {
	id = cfg.MicrosoftClientID
	if svc.MicrosoftClientID != nil && *svc.MicrosoftClientID != "" {
		id = *svc.MicrosoftClientID
	}
	return id
}

func (h *MicrosoftHandlers) clientSecret(svc *gen.Service) (string, error) {
	return resolveClientSecret(h.getenv, svc, "microsoft", svc.MicrosoftClientSecretEnv, svc.MicrosoftClientSecret, h.cfg.MicrosoftClientSecret)
}
