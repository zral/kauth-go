package auth

import (
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/mail"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

// --- Rate limiter ---

type rateLimiterEntry struct {
	count     int
	windowEnd time.Time
}

type RateLimiter struct {
	mu      sync.Mutex
	entries map[string]*rateLimiterEntry
	limit   int
	window  time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{entries: make(map[string]*rateLimiterEntry), limit: limit, window: window}
}

func (rl *RateLimiter) Allow(email string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	e, ok := rl.entries[email]
	if !ok || now.After(e.windowEnd) {
		rl.entries[email] = &rateLimiterEntry{count: 1, windowEnd: now.Add(rl.window)}
		return true
	}
	if e.count >= rl.limit {
		return false
	}
	e.count++
	return true
}

// --- Magic handlers ---

type MagicHandlers struct {
	cfg     config.Config
	queries *gen.Queries
	mailer  *mail.Service
	issuer  *token.Issuer
	refresh *token.RefreshService
	reg     *service.Registry
	aud     *audit.Service
	rl      *RateLimiter
	tmpl    *template.Template
}

func NewMagicHandlers(cfg config.Config, q *gen.Queries, m *mail.Service, iss *token.Issuer,
	ref *token.RefreshService, reg *service.Registry, aud *audit.Service, tmpl *template.Template) *MagicHandlers {
	return &MagicHandlers{cfg: cfg, queries: q, mailer: m, issuer: iss, refresh: ref,
		reg: reg, aud: aud, rl: NewRateLimiter(3, 15*time.Minute), tmpl: tmpl}
}

// ShowForm — GET /magic-login
func (h *MagicHandlers) ShowForm(w http.ResponseWriter, r *http.Request) {
	svc := h.reg.ResolveOrDefault(r.Host, r.URL.Query().Get("service"), "")
	var logoHTML template.HTML
	if svc.LogoHtml != nil {
		logoHTML = template.HTML(*svc.LogoHtml) // #nosec G203 — validert ved insert
	}
	data := LoginPageData{
		Service:  svc,
		LogoHTML: logoHTML,
		Error:    r.URL.Query().Get("error"),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.tmpl.ExecuteTemplate(w, "magic-login.html", data)
}

// RequestLink — POST /magic-login
// Returnerer alltid 200 (anti-enumeration). Minimum 200ms responstid.
func (h *MagicHandlers) RequestLink(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		if d := time.Since(start); d < 200*time.Millisecond {
			time.Sleep(200*time.Millisecond - d)
		}
	}()
	_ = r.ParseForm()
	email := r.FormValue("email")
	// Leser "service" (ny template) med fallback til "service_id" (gammel form)
	serviceID := r.FormValue("service")
	if serviceID == "" {
		serviceID = r.FormValue("service_id")
	}
	svc := h.reg.ResolveOrDefault(r.Host, serviceID, "")

	if !h.rl.Allow(email) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("sjekk e-post"))
		return
	}

	b := make([]byte, 32)
	_, _ = rand.Read(b)
	plainToken := hex.EncodeToString(b)
	now := time.Now().UTC()

	redirectURI := r.URL.Query().Get("redirect_uri")
	var redirectURIPtr *string
	if redirectURI != "" {
		redirectURIPtr = &redirectURI
	}

	_ = h.queries.InsertMagicToken(r.Context(), gen.InsertMagicTokenParams{
		Token:       plainToken,
		Email:       email,
		ServiceID:   &serviceID,
		RedirectUri: redirectURIPtr,
		ExpiresAt:   now.Add(15 * time.Minute).Format(time.RFC3339),
		CreatedAt:   now.Format(time.RFC3339),
	})

	fromName := svc.EmailFromName
	link := h.cfg.BaseURL + "/magic-login/" + plainToken + "?service=" + serviceID
	_ = h.mailer.SendMagicLink(email, fromName, link)

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("sjekk e-post"))
}

// VerifyToken — GET /magic-login/{token}
func (h *MagicHandlers) VerifyToken(w http.ResponseWriter, r *http.Request) {
	svcID := r.URL.Query().Get("service")
	svc := h.reg.ResolveOrDefault(r.Host, svcID, "")
	ip := ClientIP(r)
	ua := r.Header.Get("User-Agent")

	magic, err := h.queries.ConsumeMagicToken(r.Context(), gen.ConsumeMagicTokenParams{
		Token:     chi.URLParam(r, "token"),
		ExpiresAt: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		http.Error(w, "ugyldig eller utløpt lenke", http.StatusUnauthorized)
		return
	}

	user, err := h.queries.GetActiveUserByEmail(r.Context(), magic.Email)
	if err != nil {
		if svc.AutoRegister != 1 {
			http.Error(w, "ingen konto funnet", http.StatusUnauthorized)
			return
		}
		defaultOrg := ""
		if svc.DefaultOrg != nil {
			defaultOrg = *svc.DefaultOrg
		}
		defaultRole := "user"
		if svc.DefaultRole != nil && *svc.DefaultRole != "" {
			defaultRole = *svc.DefaultRole
		}
		user, err = h.queries.CreateUser(r.Context(), gen.CreateUserParams{
			Email:     magic.Email,
			Roles:     defaultRole,
			Orgs:      defaultOrg,
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		})
		if err != nil {
			http.Error(w, "intern feil", http.StatusInternalServerError)
			return
		}
	}

	accessToken, err := h.issuer.IssueAccess(user, *svc)
	if err != nil {
		http.Error(w, "kunne ikke utstede token", http.StatusInternalServerError)
		return
	}
	refreshToken, err := h.refresh.Issue(r.Context(), user, *svc, ip, ua)
	if err != nil {
		http.Error(w, "kunne ikke utstede refresh-token", http.StatusInternalServerError)
		return
	}
	setAuthCookies(w, svc, accessToken, refreshToken)

	lastLogin := time.Now().UTC().Format(time.RFC3339)
	_ = h.queries.UpdateUserLastLogin(r.Context(), gen.UpdateUserLastLoginParams{LastLogin: &lastLogin, Email: user.Email})
	h.aud.Log(r.Context(), audit.Event{Type: "magic_link_login", AuthMethod: "magic_link", Email: user.Email, ServiceID: svc.ID, IP: ip, UA: ua, Success: true})
	http.Redirect(w, r, "/dispatch?service="+svc.ID, http.StatusFound)
}

