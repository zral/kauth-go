package auth

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

// DispatchHandler håndterer post-login routing og utlogging.
type DispatchHandler struct {
	Registry     *service.Registry
	Issuer       *token.Issuer
	DefaultSvcID string // ID til default-tjeneste for cookie-navn
}

// readRedirectCookie leser og URL-dekoder redirect_uri-cookien.
func readRedirectCookie(r *http.Request) string {
	c, err := r.Cookie("redirect_uri")
	if err != nil {
		return ""
	}
	v, _ := url.QueryUnescape(c.Value)
	return strings.Trim(v, `"`)
}

// ServeDispatch håndterer GET /dispatch.
// Tre-nivå routing:
//  1. redirect_uri-cookie → IsAllowedCallback → redirect (slett cookie)
//  2. auth_token-cookie → Verify → org-match mot DefaultOrg → redirect CallbackUrl
//  3. Fallback til default-tjenestens CallbackUrl
func (h *DispatchHandler) ServeDispatch(w http.ResponseWriter, r *http.Request) {
	// Nivå 1: eksplisitt redirect_uri fra cookie
	if redirectURI := readRedirectCookie(r); redirectURI != "" {
		allSvcs := h.Registry.All()
		for _, svc := range allSvcs {
			if h.Registry.IsAllowedCallback(svc, redirectURI) {
				// Slett redirect_uri-cookie
				http.SetCookie(w, &http.Cookie{
					Name:     "redirect_uri",
					Value:    "",
					Path:     "/",
					MaxAge:   -1,
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteLaxMode,
				})
				http.Redirect(w, r, redirectURI, http.StatusSeeOther)
				return
			}
		}
	}

	// Hent default-tjeneste for å lese riktig cookie-navn
	defaultSvc := h.Registry.ResolveOrDefault("", h.DefaultSvcID, "")

	// Nivå 2: org-match via JWT
	cookieName := "auth_token"
	if defaultSvc != nil {
		cookieName = defaultSvc.JwtCookieName
	}
	if c, err := r.Cookie(cookieName); err == nil && c.Value != "" {
		if claims, err := h.Issuer.Verify(c.Value); err == nil {
			allSvcs := h.Registry.All()
			for _, svc := range allSvcs {
				if svc.DefaultOrg == nil {
					continue
				}
				for _, org := range claims.Org {
					if org == *svc.DefaultOrg {
						http.Redirect(w, r, svc.CallbackUrl, http.StatusSeeOther)
						return
					}
				}
			}
		}
	}

	// Nivå 3: fallback til default-tjenestens callback
	if defaultSvc != nil {
		http.Redirect(w, r, defaultSvc.CallbackUrl, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ServeLogout håndterer GET /logout.
// Sletter auth_token og refresh_token, redirecter til redirect_uri eller /login.
func (h *DispatchHandler) ServeLogout(w http.ResponseWriter, r *http.Request) {
	defaultSvc := h.Registry.ResolveOrDefault("", h.DefaultSvcID, "")

	// Slett auth_token-cookie
	cookieName := "auth_token"
	if defaultSvc != nil {
		cookieName = defaultSvc.JwtCookieName
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   0,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Slett refresh_token-cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		MaxAge:   0,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect til oppgitt URI hvis den er registrert, ellers /login
	if redirectURI := r.URL.Query().Get("redirect_uri"); redirectURI != "" {
		allSvcs := h.Registry.All()
		for _, svc := range allSvcs {
			if h.Registry.IsAllowedCallback(svc, redirectURI) {
				http.Redirect(w, r, redirectURI, http.StatusSeeOther)
				return
			}
		}
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
