package auth

import (
	"os"
	"net/http"
	"time"

	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

// setAuthCookies setter JWT-cookie og refresh_token-cookie.
// refresh_token bruker SameSite=None slik at SPA-er på andre domener
// kan bruke POST /token cross-origin med cookie.
func setAuthCookies(w http.ResponseWriter, svc *gen.Service, accessToken, refreshToken string) {
	ttl, err := token.ParseISO8601Duration(svc.AccessTokenTtl)
	if err != nil || ttl <= 0 {
		ttl = 30 * 24 * time.Hour
	}
	http.SetCookie(w, &http.Cookie{
		Name:     svc.JwtCookieName,
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true,
		Secure: os.Getenv("KAUTH_INSECURE_COOKIES") != "true",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure: os.Getenv("KAUTH_INSECURE_COOKIES") != "true",
		SameSite: http.SameSiteNoneMode,
		MaxAge:   30 * 24 * 3600,
	})
}

// setRefreshCookie setter kun refresh_token-cookien (HttpOnly, Secure, SameSite=None, 30 dager).
// Brukes av callback-handlers etter overgang til URL-token-flyt.
func setRefreshCookie(w http.ResponseWriter, refreshToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   os.Getenv("KAUTH_INSECURE_COOKIES") != "true",
		SameSite: http.SameSiteNoneMode,
		MaxAge:   30 * 24 * 3600,
	})
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", HttpOnly: true, Secure: os.Getenv("KAUTH_INSECURE_COOKIES") != "true", MaxAge: -1})
}

