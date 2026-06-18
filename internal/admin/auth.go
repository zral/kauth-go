package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	googleOAuth2 "golang.org/x/oauth2/google"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/auth"
	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/mail"
	"github.com/zral/kauth-go/internal/token"
)

// AuthHandler håndterer admin-innlogging via magic-token.
type AuthHandler struct {
	queries  *gen.Queries
	issuer   *token.Issuer
	mailer   *mail.Service
	auditor  *audit.Service
	cfg      *config.Config
	loginTpl *template.Template
}

func NewAuthHandler(
	queries *gen.Queries,
	issuer *token.Issuer,
	mailer *mail.Service,
	auditor *audit.Service,
	cfg *config.Config,
) *AuthHandler {
	tpl := template.Must(template.ParseFiles("templates/admin/login.html"))
	return &AuthHandler{
		queries:  queries,
		issuer:   issuer,
		mailer:   mailer,
		auditor:  auditor,
		cfg:      cfg,
		loginTpl: tpl,
	}
}

type loginPageData struct {
	Message string
	IsError bool
	Sent    bool
}

// HandleLoginGet rendrer innloggingssiden.
func (h *AuthHandler) HandleLoginGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.loginTpl.Execute(w, loginPageData{})
}

// HandleLoginPost mottar e-post, sjekker "konge"-rolle, sender magic-token.
// Returnerer alltid 200 "sjekk innboksen" for å unngå bruker-enumerering.
func (h *AuthHandler) HandleLoginPost(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()

	// Konstant minimumsforsinkelse mot timing-angrep.
	start := time.Now()
	defer func() {
		if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
			time.Sleep(200*time.Millisecond - elapsed)
		}
	}()

	// Forsøk å sende magic-link, men avslør aldri feil til klienten.
	_ = h.tryIssueMagicLink(r)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.loginTpl.Execute(w, loginPageData{
		Message: "Sjekk innboksen — lenken er gyldig i 15 minutter.",
		Sent:    true,
	})
}

func (h *AuthHandler) tryIssueMagicLink(r *http.Request) error {
	ctx := r.Context()
	email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))

	user, err := h.queries.GetActiveUserByEmail(ctx, email)
	if err != nil {
		h.auditor.Log(ctx, audit.Event{
			Type:    "admin_magic_link_requested",
			Email:   email,
			IP:      extractIP(r),
			UA:      r.UserAgent(),
			Success: false,
			Details: "bruker ikke funnet",
		})
		return err
	}

	if !hasRole(user.Roles, "konge") {
		h.auditor.Log(ctx, audit.Event{
			Type:    "admin_magic_link_requested",
			Email:   email,
			IP:      extractIP(r),
			UA:      r.UserAgent(),
			Success: false,
			Details: "mangler konge-rolle",
		})
		return nil
	}

	rawToken, err := generateToken()
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	expiresAt := now.Add(15 * time.Minute)
	err = h.queries.InsertMagicToken(ctx, gen.InsertMagicTokenParams{
		Token:       rawToken,
		Email:       email,
		ServiceID:   nil,
		RedirectUri: nil,
		CreatedAt:   now.Format("2006-01-02T15:04:05Z"),
		ExpiresAt:   expiresAt.Format("2006-01-02T15:04:05Z"),
	})
	if err != nil {
		return err
	}

	verifyURL := h.cfg.BaseURL + "/admin/verify?token=" + rawToken
	fromName := "kauth Admin"
	if sendErr := h.mailer.SendMagicLink(email, fromName, verifyURL); sendErr != nil {
		return sendErr
	}

	h.auditor.Log(ctx, audit.Event{
		Type:    "admin_magic_link_requested",
		Email:   email,
		IP:      extractIP(r),
		UA:      r.UserAgent(),
		Success: true,
	})
	return nil
}

// HandleVerify verifiserer magic-token, setter admin_token-cookie og redirecter.
func (h *AuthHandler) HandleVerify(w http.ResponseWriter, r *http.Request) {
	rawToken := strings.TrimSpace(r.URL.Query().Get("token"))
	if rawToken == "" {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	ctx := r.Context()
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	mt, err := h.queries.ConsumeMagicToken(ctx, gen.ConsumeMagicTokenParams{
		Token:     rawToken,
		ExpiresAt: now,
	})
	if err != nil {
		h.auditor.Log(ctx, audit.Event{
			Type:    "admin_login",
			IP:      extractIP(r),
			UA:      r.UserAgent(),
			Success: false,
			Details: "ugyldig eller utløpt token",
		})
		http.Redirect(w, r, "/admin/login?err=ugyldig_token", http.StatusSeeOther)
		return
	}

	user, err := h.queries.GetActiveUserByEmail(ctx, mt.Email)
	if err != nil || !hasRole(user.Roles, "konge") {
		h.auditor.Log(ctx, audit.Event{
			Type:    "admin_login",
			Email:   mt.Email,
			IP:      extractIP(r),
			UA:      r.UserAgent(),
			Success: false,
			Details: "bruker ikke funnet eller mangler konge-rolle",
		})
		http.Redirect(w, r, "/admin/login?err=ingen_tilgang", http.StatusSeeOther)
		return
	}

	adminToken, err := h.issuer.IssueAdmin(user, h.cfg.AdminTokenTTL)
	if err != nil {
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "admin_token",
		Value:    adminToken,
		Path:     "/admin",
		HttpOnly: true,
		Secure: os.Getenv("KAUTH_INSECURE_COOKIES") != "true",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(h.cfg.AdminTokenTTL.Seconds()),
	})

	h.auditor.Log(ctx, audit.Event{
		Type:    "admin_login",
		Email:   user.Email,
		IP:      extractIP(r),
		UA:      r.UserAgent(),
		Success: true,
	})
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// HandleLogout sletter admin_token-cookie og redirecter til innloggingssiden.
func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	// Logg kun hvis vi kan hente e-post fra eksisterende cookie.
	if c, err := r.Cookie("admin_token"); err == nil {
		if claims, err := h.issuer.Verify(c.Value); err == nil {
			h.auditor.Log(r.Context(), audit.Event{
				Type:    "admin_logout",
				Email:   claims.Email,
				IP:      extractIP(r),
				UA:      r.UserAgent(),
				Success: true,
			})
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "admin_token",
		Value:    "",
		Path:     "/admin",
		HttpOnly: true,
		Secure: os.Getenv("KAUTH_INSECURE_COOKIES") != "true",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

// HandleGoogleInitiate — GET /admin/google-init
// Starter Google OAuth-flyten for admin-innlogging.
func (h *AuthHandler) HandleGoogleInitiate(w http.ResponseWriter, r *http.Request) {
	nonce, err := generateToken()
	if err != nil {
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}
	state := auth.SignState(h.cfg.OIDCStateSecret, "admin", nonce)
	oauthCfg := &oauth2.Config{
		ClientID:    h.cfg.GoogleClientID,
		Endpoint:    googleOAuth2.Endpoint,
		RedirectURL: h.cfg.BaseURL + "/admin/google-callback",
		Scopes:      []string{oidc.ScopeOpenID, "email", "profile"},
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "admin_oidc_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   os.Getenv("KAUTH_INSECURE_COOKIES") != "true",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
	authURL := oauthCfg.AuthCodeURL(state, oauth2.SetAuthURLParam("prompt", "select_account"))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleGoogleCallback — GET /admin/google-callback
// Fullfører Google OAuth-flyten og utsteder admin-token.
func (h *AuthHandler) HandleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sc, err := r.Cookie("admin_oidc_state")
	if err != nil || sc.Value != r.URL.Query().Get("state") {
		http.Redirect(w, r, "/admin/login?err=ugyldig_state", http.StatusSeeOther)
		return
	}
	if _, ok := auth.VerifyState(h.cfg.OIDCStateSecret, sc.Value); !ok {
		http.Redirect(w, r, "/admin/login?err=ugyldig_state", http.StatusSeeOther)
		return
	}

	oauthCfg := &oauth2.Config{
		ClientID:     h.cfg.GoogleClientID,
		ClientSecret: h.cfg.GoogleClientSecret,
		Endpoint:     googleOAuth2.Endpoint,
		RedirectURL:  h.cfg.BaseURL + "/admin/google-callback",
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
	oauth2Token, err := oauthCfg.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Redirect(w, r, "/admin/login?err=token_utveksling_feilet", http.StatusSeeOther)
		return
	}

	provider, err := oidc.NewProvider(context.Background(), "https://accounts.google.com")
	if err != nil {
		http.Error(w, "OIDC discovery feilet", http.StatusInternalServerError)
		return
	}
	rawIDToken, _ := oauth2Token.Extra("id_token").(string)
	idToken, err := provider.Verifier(&oidc.Config{ClientID: h.cfg.GoogleClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		http.Redirect(w, r, "/admin/login?err=ugyldig_token", http.StatusSeeOther)
		return
	}

	var cl struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := idToken.Claims(&cl); err != nil {
		http.Redirect(w, r, "/admin/login?err=ugyldig_token", http.StatusSeeOther)
		return
	}

	user, err := h.queries.GetActiveUserByEmail(ctx, cl.Email)
	if err != nil || !hasRole(user.Roles, "konge") {
		h.auditor.Log(ctx, audit.Event{
			Type:       "admin_google_login",
			AuthMethod: "google",
			Email:      cl.Email,
			IP:         extractIP(r),
			UA:         r.UserAgent(),
			Success:    false,
			Details:    "ingen tilgang — mangler konge-rolle",
		})
		http.Redirect(w, r, "/admin/login?err=ingen_tilgang", http.StatusSeeOther)
		return
	}

	adminToken, err := h.issuer.IssueAdmin(user, h.cfg.AdminTokenTTL)
	if err != nil {
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "admin_token",
		Value:    adminToken,
		Path:     "/admin",
		HttpOnly: true,
		Secure:   os.Getenv("KAUTH_INSECURE_COOKIES") != "true",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(h.cfg.AdminTokenTTL.Seconds()),
	})

	// Slett OIDC state-cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "admin_oidc_state",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	h.auditor.Log(ctx, audit.Event{
		Type:       "admin_google_login",
		AuthMethod: "google",
		Email:      user.Email,
		IP:         extractIP(r),
		UA:         r.UserAgent(),
		Success:    true,
	})
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// hasRole sjekker om en kommaseparert roles-streng inneholder targetRole.
func hasRole(roles, targetRole string) bool {
	for _, r := range strings.Split(roles, ",") {
		if strings.TrimSpace(r) == targetRole {
			return true
		}
	}
	return false
}

// generateToken lager et kryptografisk tilfeldig hex-token (256-bit).
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// extractIP henter klient-IP fra Cloudflare → X-Forwarded-For → RemoteAddr.
func extractIP(r *http.Request) string {
	return audit.ExtractIP(
		r.Header.Get("CF-Connecting-IP"),
		r.Header.Get("X-Forwarded-For"),
		r.RemoteAddr,
	)
}
