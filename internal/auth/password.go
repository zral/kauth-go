package auth

import (
	"errors"
	"log/slog"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

// PasswordHandlers håndterer passord-innlogging og OAuth2 refresh-grant.
type PasswordHandlers struct {
	queries   *gen.Queries
	issuer    *token.Issuer
	refresh   *token.RefreshService
	reg       *service.Registry
	aud       *audit.Service
	completer *loginCompleter
	// passwordLoginEnabled er den globale bryteren (KAUTH_PASSWORD_LOGIN_ENABLED).
	// Den gjelder /do-login uansett tjenestens auth_password.
	passwordLoginEnabled bool
	// corsOrigins er KAUTH_CORS_ORIGINS; brukes til Origin-sjekk på refresh-grant.
	corsOrigins []string
}

// WithCORSOrigins setter origin-allowlisten som refresh-grant sjekker mot.
func (h *PasswordHandlers) WithCORSOrigins(origins []string) *PasswordHandlers {
	h.corsOrigins = origins
	if len(origins) == 0 {
		slog.Warn("refresh-allowlist er tom: all refresh med Origin-header avvises (KAUTH_CORS_ORIGINS)")
	} else {
		slog.Info("refresh-allowlist lastet", "origins", len(origins))
	}
	return h
}

func NewPasswordHandlers(q *gen.Queries, iss *token.Issuer, ref *token.RefreshService, reg *service.Registry, aud *audit.Service, passwordLoginEnabled bool) *PasswordHandlers {
	return &PasswordHandlers{queries: q, issuer: iss, refresh: ref, reg: reg, aud: aud, passwordLoginEnabled: passwordLoginEnabled,
		completer: &loginCompleter{queries: q, issuer: iss, refresh: ref, aud: aud}}
}

// DoLogin — POST /do-login
func (h *PasswordHandlers) DoLogin(w http.ResponseWriter, r *http.Request) {
	// Før alt annet: ingen skjemaparsing, brukeroppslag eller bcrypt når
	// bryteren er av.
	if !h.passwordLoginEnabled {
		http.Error(w, "passord-innlogging ikke aktivert", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	email := NormalizeEmail(r.FormValue("email"))
	password := r.FormValue("password")
	svcID := r.FormValue("service_id")
	svc := resolveRequestedService(h.reg, r, svcID)

	if svc.AuthPassword != 1 {
		http.Error(w, "passord-innlogging ikke aktivert", http.StatusForbidden)
		return
	}
	ip, ua := ClientIP(r), r.Header.Get("User-Agent")

	user, err := h.queries.GetActiveUserByEmail(r.Context(), email)
	if err != nil || user.PasswordHash == nil || *user.PasswordHash == "" {
		h.aud.Log(r.Context(), audit.Event{Type: "login_failed", AuthMethod: "password", Email: email, ServiceID: svc.ID, IP: ip, UA: ua, Success: false})
		http.Error(w, "ugyldig e-post eller passord", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte(password)); err != nil {
		h.aud.Log(r.Context(), audit.Event{Type: "login_failed", AuthMethod: "password", Email: email, ServiceID: svc.ID, IP: ip, UA: ua, Success: false})
		http.Error(w, "ugyldig e-post eller passord", http.StatusUnauthorized)
		return
	}

	// require_role/enforce_org håndheves i complete, som er felles for alle
	// fire metodene. Passord-login ble tidligere aldri sjekket mot disse
	// (github.com/zral/kauth-go/issues/3).
	if err := h.completer.complete(w, r, svc, user, loginPassword); err != nil {
		if !errors.Is(err, errPolicyDenied) {
			http.Error(w, "intern feil", http.StatusInternalServerError)
			return
		}
		h.aud.Log(r.Context(), audit.Event{Type: "login_failed", AuthMethod: "password", Email: user.Email, ServiceID: svc.ID, IP: ip, UA: ua, Success: false, Details: err.Error()})
		http.Error(w, err.Error(), http.StatusForbidden)
	}
}
