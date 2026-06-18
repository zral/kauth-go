package main

import (
	"context"
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/auth"
	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/mail"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

func main() {
	// --- Konfigurasjon ---
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("konfigurasjonsfeil: %v", err)
	}

	// --- Logging ---
	level := slog.LevelInfo
	if cfg.LogLevel == "debug" {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})))

	// --- Database + migrasjoner ---
	sqlDB, queries, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer sqlDB.Close()

	// --- Avhengigheter ---
	auditSvc := audit.NewService(queries)
	issuer, err := token.NewIssuer(cfg.PrivateKey, cfg.PublicKey, cfg.Issuer, cfg.AccessTokenTTL, cfg.AdminTokenTTL)
	if err != nil {
		log.Fatalf("issuer: %v", err)
	}
	refreshSvc := token.NewRefreshService(queries, auditSvc)
	registry := service.NewRegistry(queries)
	if err := registry.Warmup(context.Background()); err != nil {
		log.Fatalf("registry warmup: %v", err)
	}
	mailer := mail.New(*cfg)

	// --- Templates ---
	tmpl := template.Must(template.ParseGlob("templates/*.html"))

	// --- Handlere ---
	magicH := auth.NewMagicHandlers(*cfg, queries, mailer, issuer, refreshSvc, registry, auditSvc, tmpl)
	googleH := auth.NewGoogleHandlers(*cfg, queries, issuer, refreshSvc, registry, auditSvc)
	msH := auth.NewMicrosoftHandlers(*cfg, queries, issuer, refreshSvc, registry, auditSvc)
	passwordH := auth.NewPasswordHandlers(queries, issuer, refreshSvc, registry, auditSvc)
	loginH := &auth.LoginHandler{Registry: registry, Templates: tmpl}
	dispatchH := &auth.DispatchHandler{
		Registry:     registry,
		Issuer:       issuer,
		DefaultSvcID: "",
	}
	meH := &auth.MeHandler{
		Issuer:     issuer,
		CookieName: "auth_token",
	}

	// --- Router ---
	r := chi.NewRouter()
	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)
	r.Use(auth.ClientIPMiddleware)

	// Statiske filer
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Login
	r.Get("/login", loginH.ServeLogin)
	r.Get("/login.html", auth.ServeLegacyLogin)
	r.Get("/login-pov.html", auth.ServeLegacyLogin)

	// Post-innlogging
	r.Get("/dispatch", dispatchH.ServeDispatch)
	r.Get("/logout", dispatchH.ServeLogout)

	// API
	r.Get("/api/me", meH.ServeMe)

	// OIDC-discovery og token — med CORS
	r.Route("/.well-known", func(r chi.Router) {
		r.Use(auth.CORSMiddleware(cfg.CORSOrigins))
		r.Get("/openid-configuration", issuer.DiscoveryHandler())
		r.Get("/jwks.json", issuer.JWKSHandler)
	})
	r.With(auth.CORSMiddleware(cfg.CORSOrigins)).Post("/token", passwordH.RefreshToken)

	// Google + Microsoft OIDC
	r.Get("/oidc-login", googleH.InitiateLogin)
	r.Get("/callback", googleH.HandleCallback)
	r.Get("/ms-oidc-login", msH.InitiateLogin)
	r.Get("/ms-callback", msH.HandleCallback)

	// Passord-login
	r.Post("/do-login", passwordH.DoLogin)

	// Magic link
	r.Get("/magic-login", magicH.ShowForm)
	r.Post("/magic-login", magicH.RequestLink)
	r.Get("/magic-login/{token}", magicH.VerifyToken)

	// Admin — se Task 14 for fullstendig admin-routing

	log.Printf("kauth lytter på :%s (issuer: %s)\n", cfg.HTTPPort, cfg.Issuer)
	if err := http.ListenAndServe(":"+cfg.HTTPPort, r); err != nil {
		log.Fatalf("server krasjet: %v", err)
	}
}
