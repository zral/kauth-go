package admin

import (
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
)

// ServicesHandler håndterer administrasjon av tjenester i admin-panelet.
type ServicesHandler struct {
	queries  *gen.Queries
	registry *service.Registry
	auditor  *audit.Service
	listTpl  *template.Template
	editTpl  *template.Template
}

func NewServicesHandler(
	queries *gen.Queries,
	registry *service.Registry,
	auditor *audit.Service,
) *ServicesHandler {
	listTpl := template.Must(template.ParseFiles("templates/admin/services.html"))
	editTpl := template.Must(template.ParseFiles("templates/admin/service-edit.html"))
	return &ServicesHandler{
		queries:  queries,
		registry: registry,
		auditor:  auditor,
		listTpl:  listTpl,
		editTpl:  editTpl,
	}
}

// HandleList viser alle tjenester (aktive og inaktive).
func (h *ServicesHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	services, err := h.queries.ListAllServices(r.Context())
	if err != nil {
		http.Error(w, "databasefeil: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.listTpl.Execute(w, map[string]interface{}{"Services": services})
}

// HandleNew rendrer skjema for ny tjeneste med fornuftige standardverdier.
func (h *ServicesHandler) HandleNew(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.editTpl.Execute(w, map[string]interface{}{
		"IsNew": true,
		"Service": gen.Service{
			AuthGoogle:     1,
			AuthMagicLink:  1,
			Active:         1,
			AccentColor:    "#2563EB",
			Theme:          "light",
			JwtCookieName:  "auth_token",
			AccessTokenTtl: "PT15M",
		},
	})
}

// HandleCreate oppretter ny tjeneste fra POST-skjema.
func (h *ServicesHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	svcID := strings.TrimSpace(r.FormValue("id"))
	if svcID == "" {
		h.renderServiceError(w, serviceFromForm(r), true, "Tjeneste-ID er påkrevd.")
		return
	}

	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	params := buildCreateParams(r, svcID, now)
	if err := h.queries.CreateService(r.Context(), params); err != nil {
		h.renderServiceError(w, serviceFromForm(r), true, "Feil ved opprettelse: "+err.Error())
		return
	}

	// Ugyldiggjør cache — ikke kritisk hvis det feiler.
	_ = h.registry.Invalidate(r.Context())

	h.auditor.Log(r.Context(), audit.Event{
		Type:      "service_created",
		ServiceID: svcID,
		IP:        extractIP(r),
		UA:        r.UserAgent(),
		Success:   true,
	})
	http.Redirect(w, r, "/admin/services", http.StatusSeeOther)
}

// HandleEdit rendrer redigeringsskjema for eksisterende tjeneste.
func (h *ServicesHandler) HandleEdit(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	services, err := h.queries.ListAllServices(r.Context())
	if err != nil {
		http.Error(w, "databasefeil", http.StatusInternalServerError)
		return
	}
	var found *gen.Service
	for i := range services {
		if services[i].ID == id {
			found = &services[i]
			break
		}
	}
	if found == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.editTpl.Execute(w, map[string]interface{}{
		"IsNew":   false,
		"Service": *found,
	})
}

// HandleUpdate lagrer endringer på eksisterende tjeneste.
func (h *ServicesHandler) HandleUpdate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	_ = r.ParseForm()
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	params := buildUpdateParams(r, id, now)
	if err := h.queries.UpdateService(r.Context(), params); err != nil {
		svc := serviceFromForm(r)
		svc.ID = id
		h.renderServiceError(w, svc, false, "Databasefeil: "+err.Error())
		return
	}

	_ = h.registry.Invalidate(r.Context())

	h.auditor.Log(r.Context(), audit.Event{
		Type:      "service_edited",
		ServiceID: id,
		IP:        extractIP(r),
		UA:        r.UserAgent(),
		Success:   true,
	})
	http.Redirect(w, r, "/admin/services", http.StatusSeeOther)
}

// buildCreateParams bygger CreateServiceParams fra HTTP-skjema-verdier.
func buildCreateParams(r *http.Request, id, now string) gen.CreateServiceParams {
	return gen.CreateServiceParams{
		ID:                    id,
		DisplayName:           r.FormValue("display_name"),
		Tagline:               nullableStr(r.FormValue("tagline")),
		Domain:                r.FormValue("domain"),
		AuthHost:              nullableStr(r.FormValue("auth_host")),
		CallbackUrl:           r.FormValue("callback_url"),
		LogoHtml:              nullableStr(r.FormValue("logo_html")),
		BgImage:               nullableStr(r.FormValue("bg_image")),
		BgCss:                 nullableStr(r.FormValue("bg_css")),
		Theme:                 defaultStr(r.FormValue("theme"), "light"),
		AccentColor:           defaultStr(r.FormValue("accent_color"), "#2563EB"),
		EmailFromName:         defaultStr(r.FormValue("email_from_name"), id),
		AutoRegister:          checkboxInt(r, "auto_register"),
		DefaultRole:           nullableStr(r.FormValue("default_role")),
		DefaultOrg:            nullableStr(r.FormValue("default_org")),
		RequireRole:           nullableStr(r.FormValue("require_role")),
		EnforceOrg:            checkboxInt(r, "enforce_org"),
		IsDefault:             checkboxInt(r, "is_default"),
		AuthGoogle:            checkboxInt(r, "auth_google"),
		AuthMicrosoft:         checkboxInt(r, "auth_microsoft"),
		AuthMagicLink:         checkboxInt(r, "auth_magic_link"),
		AuthPassword:          checkboxInt(r, "auth_password"),
		GoogleClientID:        nullableStr(r.FormValue("google_client_id")),
		GoogleClientSecret:    nullableStr(r.FormValue("google_client_secret")),
		MicrosoftClientID:     nullableStr(r.FormValue("microsoft_client_id")),
		MicrosoftClientSecret: nullableStr(r.FormValue("microsoft_client_secret")),
		JwtCookieName:         defaultStr(r.FormValue("jwt_cookie_name"), "auth_token"),
		AccessTokenTtl:        defaultStr(r.FormValue("access_token_ttl"), "PT15M"),
		RefreshTokenMaxAge:    nullableStr(r.FormValue("refresh_token_max_age")),
		Active:                checkboxInt(r, "active"),
		UpdatedAt:             now,
	}
}

// buildUpdateParams bygger UpdateServiceParams fra buildCreateParams.
func buildUpdateParams(r *http.Request, id, now string) gen.UpdateServiceParams {
	cp := buildCreateParams(r, id, now)
	return gen.UpdateServiceParams{
		DisplayName:           cp.DisplayName,
		Tagline:               cp.Tagline,
		Domain:                cp.Domain,
		AuthHost:              cp.AuthHost,
		CallbackUrl:           cp.CallbackUrl,
		LogoHtml:              cp.LogoHtml,
		BgImage:               cp.BgImage,
		BgCss:                 cp.BgCss,
		Theme:                 cp.Theme,
		AccentColor:           cp.AccentColor,
		EmailFromName:         cp.EmailFromName,
		AutoRegister:          cp.AutoRegister,
		DefaultRole:           cp.DefaultRole,
		DefaultOrg:            cp.DefaultOrg,
		RequireRole:           cp.RequireRole,
		EnforceOrg:            cp.EnforceOrg,
		IsDefault:             cp.IsDefault,
		AuthGoogle:            cp.AuthGoogle,
		AuthMicrosoft:         cp.AuthMicrosoft,
		AuthMagicLink:         cp.AuthMagicLink,
		AuthPassword:          cp.AuthPassword,
		GoogleClientID:        cp.GoogleClientID,
		GoogleClientSecret:    cp.GoogleClientSecret,
		MicrosoftClientID:     cp.MicrosoftClientID,
		MicrosoftClientSecret: cp.MicrosoftClientSecret,
		JwtCookieName:         cp.JwtCookieName,
		AccessTokenTtl:        cp.AccessTokenTtl,
		RefreshTokenMaxAge:    cp.RefreshTokenMaxAge,
		Active:                cp.Active,
		UpdatedAt:             now,
		ID:                    id,
	}
}

// Hjelpefunksjoner for skjemabehandling — delt mellom auth.go, users.go og services.go.

func nullableStr(s string) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return &s
}

func defaultStr(s, def string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	return s
}

func checkboxInt(r *http.Request, name string) int64 {
	if r.FormValue(name) == "1" {
		return 1
	}
	return 0
}

// serviceFromForm bygger en gen.Service fra skjemafelter for feilrendering.
func serviceFromForm(r *http.Request) gen.Service {
	return gen.Service{
		ID:             r.FormValue("id"),
		DisplayName:    r.FormValue("display_name"),
		Domain:         r.FormValue("domain"),
		CallbackUrl:    r.FormValue("callback_url"),
		AccentColor:    defaultStr(r.FormValue("accent_color"), "#2563EB"),
		Theme:          defaultStr(r.FormValue("theme"), "light"),
		JwtCookieName:  defaultStr(r.FormValue("jwt_cookie_name"), "auth_token"),
		AccessTokenTtl: defaultStr(r.FormValue("access_token_ttl"), "PT15M"),
		Active:         checkboxInt(r, "active"),
		AuthGoogle:     checkboxInt(r, "auth_google"),
		AuthMagicLink:  checkboxInt(r, "auth_magic_link"),
		AuthMicrosoft:  checkboxInt(r, "auth_microsoft"),
		AuthPassword:   checkboxInt(r, "auth_password"),
		IsDefault:      checkboxInt(r, "is_default"),
		AutoRegister:   checkboxInt(r, "auto_register"),
	}
}

func (h *ServicesHandler) renderServiceError(w http.ResponseWriter, svc gen.Service, isNew bool, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnprocessableEntity)
	_ = h.editTpl.Execute(w, map[string]interface{}{
		"IsNew":   isNew,
		"Service": svc,
		"Error":   errMsg,
	})
}
