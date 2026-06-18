package auth

import (
	"net/http"
	"time"

	"github.com/zral/kauth-go/internal/db/gen"
)

// setAuthCookies setter JWT-cookie og refresh_token-cookie.
// refresh_token bruker SameSite=None slik at SPA-er på andre domener
// kan bruke POST /token cross-origin med cookie.
func setAuthCookies(w http.ResponseWriter, svc *gen.Service, accessToken, refreshToken string) {
	ttl := parseTTL(svc.AccessTokenTtl, 30*24*time.Hour)
	http.SetCookie(w, &http.Cookie{
		Name:     svc.JwtCookieName,
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
		MaxAge:   30 * 24 * 3600,
	})
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", HttpOnly: true, Secure: true, MaxAge: -1})
}

// parseTTL konverterer et ISO 8601-durasjonsstreng til time.Duration.
// Kun de vanligste variantene dekkes her — token-pakken har full parser,
// men circular-import hindrer gjenbruk. TODO: samle i felles pkg (Task 10+).
func parseTTL(iso string, fallback time.Duration) time.Duration {
	if iso == "" {
		return fallback
	}
	switch iso {
	case "PT15M":
		return 15 * time.Minute
	case "PT30M":
		return 30 * time.Minute
	case "PT1H":
		return time.Hour
	case "PT8H":
		return 8 * time.Hour
	case "P1D":
		return 24 * time.Hour
	case "P7D":
		return 7 * 24 * time.Hour
	case "P30D":
		return 30 * 24 * time.Hour
	}
	return fallback
}
