package auth

import (
	"os"
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

// appendTokenAndRT bygger endelig redirect-URL med token som query-param og rt som fragment.
func appendTokenAndRT(target, token, rt string) string {
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	u := target + sep + "token=" + url.QueryEscape(token)
	if rt != "" {
		u += "#rt=" + url.QueryEscape(rt)
	}
	return u
}

// ServeDispatch håndterer GET /dispatch.
// Leser token og rt fra URL query-params (ikke cookies — cross-host cookies virker ikke).
// Tre-nivå routing:
//  1. redirect_uri-cookie → IsAllowedCallback → redirect med ?token=#rt (slett cookie)
//  2. token-claim org → match mot service.DefaultOrg → redirect CallbackUrl
//  3. Fallback til default-tjenestens CallbackUrl
func (h *DispatchHandler) ServeDispatch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	jwtToken := q.Get("token")
	rt := q.Get("rt")

	// Mangler token → tilbake til login
	if jwtToken == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Verifiser token
	claims, err := h.Issuer.Verify(jwtToken)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	clearRedirectCookie := &http.Cookie{
		Name:     "redirect_uri",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   os.Getenv("KAUTH_INSECURE_COOKIES") != "true",
		SameSite: http.SameSiteLaxMode,
	}

	// Nivå 1: eksplisitt redirect_uri fra cookie (allerede validert mot allowlist)
	if redirectURI := readRedirectCookie(r); redirectURI != "" {
		allSvcs := h.Registry.All()
		for _, svc := range allSvcs {
			if h.Registry.IsAllowedCallback(svc, redirectURI) {
				http.SetCookie(w, clearRedirectCookie)
				http.Redirect(w, r, appendTokenAndRT(redirectURI, jwtToken, rt), http.StatusSeeOther)
				return
			}
		}
	}

	// Nivå 2: host-match — bruker kom inn via en service-spesifikk auth-host
	// (auth.spekto.live → spekto, auth.lilleklo.work → vinkjeller).
	// Dette må vinne over org-match for at f.eks. en konge med "lars" i orgs
	// som logger inn på auth.spekto.live skal lande på spekto-app, ikke klarsyn.
	if r.Host != "" {
		hostLc := strings.ToLower(r.Host)
		allSvcs := h.Registry.All()
		for _, svc := range allSvcs {
			if svc.AuthHost != nil && strings.ToLower(*svc.AuthHost) == hostLc {
				http.SetCookie(w, clearRedirectCookie)
				http.Redirect(w, r, appendTokenAndRT(svc.CallbackUrl, jwtToken, rt), http.StatusSeeOther)
				return
			}
		}
	}

	// Nivå 3: org-match via JWT-claims
	allSvcs := h.Registry.All()
	for _, svc := range allSvcs {
		if svc.DefaultOrg == nil {
			continue
		}
		for _, org := range claims.Org {
			if org == *svc.DefaultOrg {
				http.SetCookie(w, clearRedirectCookie)
				http.Redirect(w, r, appendTokenAndRT(svc.CallbackUrl, jwtToken, rt), http.StatusSeeOther)
				return
			}
		}
	}

	// Nivå 3: fallback til default-tjenestens callback
	defaultSvc := h.Registry.ResolveOrDefault("", h.DefaultSvcID, "")
	if defaultSvc != nil {
		http.SetCookie(w, clearRedirectCookie)
		http.Redirect(w, r, appendTokenAndRT(defaultSvc.CallbackUrl, jwtToken, rt), http.StatusSeeOther)
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
		Secure: os.Getenv("KAUTH_INSECURE_COOKIES") != "true",
		SameSite: http.SameSiteLaxMode,
	})

	// Slett refresh_token-cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		MaxAge:   0,
		HttpOnly: true,
		Secure: os.Getenv("KAUTH_INSECURE_COOKIES") != "true",
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
