package auth

import (
	"html/template"
	"net/http"

	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
)

// LoginPageData er template-data for login.html og magic-login.html.
type LoginPageData struct {
	Service     *gen.Service
	LogoHTML    template.HTML // konvertert fra Service.LogoHtml — rå HTML, ikke escaped
	RedirectURI string
	Error       string
}

// LoginHandler rendrer login-siden.
type LoginHandler struct {
	Registry  *service.Registry
	Templates *template.Template
}

// ServeLogin håndterer GET /login.
// Resolver tjeneste fra ?service=ID-parameter eller host-header.
func (h *LoginHandler) ServeLogin(w http.ResponseWriter, r *http.Request) {
	serviceID := r.URL.Query().Get("service")
	redirectURI := r.URL.Query().Get("redirect_uri")

	svc := h.Registry.ResolveOrDefault(r.Host, serviceID, redirectURI)
	if svc == nil {
		http.Error(w, "ukjent tjeneste", http.StatusBadRequest)
		return
	}

	var logoHTML template.HTML
	if svc.LogoHtml != nil {
		logoHTML = template.HTML(*svc.LogoHtml) // #nosec G203 — validert ved insert
	}

	data := LoginPageData{
		Service:     svc,
		LogoHTML:    logoHTML,
		RedirectURI: redirectURI,
		Error:       r.URL.Query().Get("error"),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.Templates.ExecuteTemplate(w, "login.html", data); err != nil {
		http.Error(w, "mal-feil", http.StatusInternalServerError)
	}
}

// ServeLegacyLogin håndterer GET /login.html og /login-pov.html → 301 /login.
func ServeLegacyLogin(w http.ResponseWriter, r *http.Request) {
	target := "/login"
	if q := r.URL.RawQuery; q != "" {
		target += "?" + q
	}
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}
