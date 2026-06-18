package auth

import (
	"context"
	"net/http"
	"strings"

	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/zral/kauth-go/internal/audit"
)

type contextKey string

const clientIPKey contextKey = "clientIP"

// ClientIPMiddleware henter klient-IP og legger den i context.
// Leser CF-Connecting-IP → X-Forwarded-For → RemoteAddr via audit.ExtractIP.
func ClientIPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := audit.ExtractIP(r.Header.Get("CF-Connecting-IP"), r.Header.Get("X-Forwarded-For"), r.RemoteAddr)
		ctx := context.WithValue(r.Context(), clientIPKey, ip)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ClientIP leser klient-IP fra context (satt av ClientIPMiddleware).
// Returnerer tom streng dersom middleware ikke kjøres — akseptabelt frem til Task 10.
func ClientIP(r *http.Request) string {
	if ip, ok := r.Context().Value(clientIPKey).(string); ok {
		return ip
	}
	return ""
}

// CORSMiddleware setter Access-Control-Allow-* headere for tillatte origins.
// Tom origins-liste betyr ingen CORS-headere. "*" tillater alle origins.
func CORSMiddleware(origins []string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool)
	for _, o := range origins {
		allowed[strings.TrimSpace(o)] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if len(allowed) == 0 || allowed["*"] || allowed[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Logger og Recoverer er re-eksporter av chi/middleware for enklere import i main.
var Logger = chimiddleware.Logger
var Recoverer = chimiddleware.Recoverer
