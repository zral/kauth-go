package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

// PasswordHandlers håndterer passord-innlogging og OAuth2 refresh-grant.
type PasswordHandlers struct {
	queries *gen.Queries
	issuer  *token.Issuer
	refresh *token.RefreshService
	reg     *service.Registry
	aud     *audit.Service
}

func NewPasswordHandlers(q *gen.Queries, iss *token.Issuer, ref *token.RefreshService, reg *service.Registry, aud *audit.Service) *PasswordHandlers {
	return &PasswordHandlers{queries: q, issuer: iss, refresh: ref, reg: reg, aud: aud}
}

// DoLogin — POST /do-login
func (h *PasswordHandlers) DoLogin(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	svcID := r.FormValue("service_id")
	svc := h.reg.ResolveOrDefault(r.Host, svcID, "")

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

	at, err := h.issuer.IssueAccess(user, *svc)
	if err != nil {
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}
	rt, err := h.refresh.Issue(r.Context(), user, *svc, ip, ua)
	if err != nil {
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}
	setRefreshCookie(w, rt)

	lastLogin := time.Now().UTC().Format(time.RFC3339)
	_ = h.queries.UpdateUserLastLogin(r.Context(), gen.UpdateUserLastLoginParams{LastLogin: &lastLogin, Email: user.Email})
	h.aud.Log(r.Context(), audit.Event{Type: "login_success", AuthMethod: "password", Email: user.Email, ServiceID: svc.ID, IP: ip, UA: ua, Success: true})
	http.Redirect(w, r, "/dispatch?token="+url.QueryEscape(at)+"&rt="+url.QueryEscape(rt), http.StatusFound)
}

// RefreshToken — POST /token
// Leser refresh token fra cookie FØR form-body (cookie prioriteres).
func (h *PasswordHandlers) RefreshToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	ip, ua := ClientIP(r), r.Header.Get("User-Agent")

	plain := ""
	if c, err := r.Cookie("refresh_token"); err == nil {
		plain = c.Value
	}
	if plain == "" {
		plain = r.FormValue("refresh_token")
	}
	if plain == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	result, err := h.refresh.Rotate(r.Context(), plain, ip, ua)
	if err != nil {
		clearCookie(w, "refresh_token")
		if errors.Is(err, token.ErrTokenReuse) {
			writeTokenError(w, http.StatusUnauthorized, "refresh_token_reused")
			return
		}
		writeTokenError(w, http.StatusUnauthorized, "invalid_or_expired_token")
		return
	}

	user, err := h.queries.GetActiveUserByEmail(r.Context(), result.Email)
	if err != nil {
		writeTokenError(w, http.StatusUnauthorized, "invalid_or_expired_token")
		return
	}

	svc := h.reg.ResolveOrDefault("", r.FormValue("service_id"), "")

	at, err := h.issuer.IssueAccess(user, *svc)
	if err != nil {
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}
	setAuthCookies(w, svc, at, result.NewToken)

	ttl, err := token.ParseISO8601Duration(svc.AccessTokenTtl)
	if err != nil || ttl <= 0 {
		ttl = 30 * 24 * time.Hour
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  at,
		"refresh_token": result.NewToken,
		"token_type":    "Bearer",
		"expires_in":    int64(ttl.Seconds()),
	})
}

func writeTokenError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
