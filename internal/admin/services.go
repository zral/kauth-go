package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
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
	auditor  auditLogger
	listTpl  *template.Template
	editTpl  *template.Template
	// providers gir leverandørseksjonen på redigeringssiden; nil i tester og
	// oppsett uten leverandørregister, og seksjonen utelates da.
	providers *ProvidersHandler
	// getenv brukes bare til å vise om en env-referanse er satt; verdien leses aldri ut av handleren.
	getenv func(string) string
}

// WithProviders kobler på leverandørseksjonen på tjenestesiden.
func (h *ServicesHandler) WithProviders(p *ProvidersHandler) *ServicesHandler {
	h.providers = p
	return h
}

func NewServicesHandler(
	queries *gen.Queries,
	registry *service.Registry,
	auditor auditLogger,
) *ServicesHandler {
	listTpl := template.Must(template.ParseFiles("templates/admin/services.html"))
	editTpl := template.Must(template.ParseFiles("templates/admin/service-edit.html"))
	return &ServicesHandler{
		queries:  queries,
		registry: registry,
		auditor:  auditor,
		listTpl:  listTpl,
		editTpl:  editTpl,
		getenv:   os.Getenv,
	}
}

// invalidateCache returnerer false når cachen er utdatert. Lagringen er allerede
// utført og rulles ikke tilbake; ellers ville admin tro at tjenesten er aktiv.
func (h *ServicesHandler) invalidateCache(r *http.Request, serviceID string) bool {
	if err := h.registry.Invalidate(r.Context()); err != nil {
		slog.Error("admin: cache-invalidering feilet etter lagring av tjeneste", "service_id", serviceID, "error", err)
		return false
	}
	return true
}

// HandleList viser alle tjenester (aktive og inaktive).
func (h *ServicesHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	services, err := h.queries.ListAllServices(r.Context())
	if err != nil {
		http.Error(w, "databasefeil: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Bare faste koder gir tekst i malen; verdien fra query-strengen speiles aldri.
	warns := warnFlags(r, "cache", "audit")
	_ = h.listTpl.Execute(w, map[string]interface{}{
		"Services": services, "WarnCache": warns["cache"], "WarnAudit": warns["audit"],
	})
}

// HandleNew rendrer skjema for ny tjeneste med fornuftige standardverdier.
func (h *ServicesHandler) HandleNew(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := map[string]interface{}{
		"IsNew": true,
		"Service": gen.Service{
			AuthGoogle:     1,
			AuthMagicLink:  1,
			Active:         1,
			AccentColor:    "#2563EB",
			Theme:          "light",
			JwtCookieName:  "auth_token",
			AccessTokenTtl: "PT15M",
			SubFormat:      "email",
			AutoLink:       1,
		},
	}
	h.addSecretStatus(data, gen.Service{}, nil)
	_ = h.editTpl.Execute(w, data)
}

// HandleCreate oppretter ny tjeneste fra POST-skjema.
func (h *ServicesHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(2 << 20); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		http.Error(w, "ugyldig skjema", http.StatusBadRequest)
		return
	}

	svcID := strings.TrimSpace(r.PostFormValue("id"))
	if svcID == "" {
		h.renderServiceError(w, serviceFromForm(r), nil, "Tjeneste-ID er påkrevd.")
		return
	}

	if err := validateAuthHost(r.PostFormValue("auth_host")); err != nil {
		h.renderServiceError(w, serviceFromForm(r), nil, err.Error())
		return
	}

	if err := validateEnforceOrg(r); err != nil {
		h.renderServiceError(w, serviceFromForm(r), nil, err.Error())
		return
	}

	if err := validateSubFormat(r); err != nil {
		h.renderServiceError(w, serviceFromForm(r), nil, err.Error())
		return
	}

	if err := validateSecretEnv(r); err != nil {
		h.renderServiceError(w, serviceFromForm(r), nil, err.Error())
		return
	}

	uploaded, uploadedPath, uploadErr := handleBgImageUpload(r, svcID)
	if uploadErr != "" {
		h.renderServiceError(w, serviceFromForm(r), nil, uploadErr)
		return
	}
	if uploaded {
		r.PostForm.Set("bg_image", uploadedPath)
	}

	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	params := buildCreateParams(r, svcID, now)
	if err := h.queries.CreateService(r.Context(), params); err != nil {
		h.renderServiceError(w, serviceFromForm(r), nil, "Feil ved opprettelse: "+err.Error())
		return
	}

	cacheOK := h.invalidateCache(r, svcID)

	// Hvert felt for seg: et manglende felt får DB-defaulten, og audit skal vise
	// det som faktisk ble lagret.
	details := fmt.Sprintf("service_created sub_format=%s auto_link=%d",
		valueOr(params.SubFormat, "email"), valueOr(params.AutoLink, int64(1)))
	details += secretEnvChanges(nil, params.GoogleClientSecretEnv, nil, params.MicrosoftClientSecretEnv)
	if uploaded {
		details += " bg_image_uploaded=" + uploadedPath
	}
	auditOK := logAdminWrite(r.Context(), h.auditor, audit.Event{
		Type:      "service_created",
		ServiceID: svcID,
		IP:        extractIP(r),
		UA:        r.UserAgent(),
		Details:   details,
		Success:   true,
	})
	http.Redirect(w, r, savedRedirect(cacheOK, auditOK), http.StatusSeeOther)
}

// HandleEdit rendrer redigeringsskjema for eksisterende tjeneste.
func (h *ServicesHandler) HandleEdit(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	found, err := h.findService(r.Context(), id)
	if err != nil {
		http.Error(w, "databasefeil", http.StatusInternalServerError)
		return
	}
	if found == nil {
		http.NotFound(w, r)
		return
	}
	data := map[string]interface{}{
		"IsNew":   false,
		"Service": withoutSecrets(*found),
	}
	h.addSecretStatus(data, *found, found)
	warns := warnFlags(r, "reload", "audit")
	data["WarnReload"], data["WarnAudit"] = warns["reload"], warns["audit"]
	if h.providers != nil {
		rows, kept, err := h.providers.serviceRows(r, id)
		if err != nil {
			slog.Error("admin: les leverandørtilordning feilet", "service_id", id, "error", err)
			http.Error(w, "databasefeil", http.StatusInternalServerError)
			return
		}
		data["ShowProviders"], data["ProviderRows"], data["KeptRows"] = true, rows, kept
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.editTpl.Execute(w, data)
}

// HandleUpdate lagrer endringer på eksisterende tjeneste.
func (h *ServicesHandler) HandleUpdate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Les-så-skriv har et lost-update-vindu: felt utenfor skjemaet (for eksempel en secret
	// som roteres direkte i SQL mellom lesing og skriving) overskrives med den leste verdien.
	// Akseptert så lenge det finnes én admin.
	existing, err := h.findService(r.Context(), id)
	if err != nil {
		http.Error(w, "databasefeil", http.StatusInternalServerError)
		return
	}
	if existing == nil {
		// Sjekkes før opplasting, slik at ukjent id ikke etterlater filer i static/.
		http.NotFound(w, r)
		return
	}

	if err := r.ParseMultipartForm(2 << 20); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		http.Error(w, "ugyldig skjema", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	if err := validateAuthHost(r.PostFormValue("auth_host")); err != nil {
		h.renderServiceError(w, overlayForm(*existing, r), existing, err.Error())
		return
	}

	if strings.TrimSpace(r.PostFormValue("display_name")) == "" ||
		strings.TrimSpace(r.PostFormValue("domain")) == "" ||
		strings.TrimSpace(r.PostFormValue("callback_url")) == "" {
		h.renderServiceError(w, overlayForm(*existing, r), existing, "Visningsnavn, domene og callback-URL er påkrevd.")
		return
	}

	if err := validateEnforceOrg(r); err != nil {
		h.renderServiceError(w, overlayForm(*existing, r), existing, err.Error())
		return
	}

	if err := validateSubFormat(r); err != nil {
		h.renderServiceError(w, overlayForm(*existing, r), existing, err.Error())
		return
	}

	if err := validateSecretEnv(r); err != nil {
		h.renderServiceError(w, overlayForm(*existing, r), existing, err.Error())
		return
	}

	uploaded, uploadedPath, uploadErr := handleBgImageUpload(r, id)
	if uploadErr != "" {
		h.renderServiceError(w, overlayForm(*existing, r), existing, uploadErr)
		return
	}
	if uploaded {
		r.PostForm.Set("bg_image", uploadedPath)
	}

	params := buildUpdateParams(r, *existing, now)
	if err := h.queries.UpdateService(r.Context(), params); err != nil {
		h.renderServiceError(w, overlayForm(*existing, r), existing, "Databasefeil: "+err.Error())
		return
	}

	cacheOK := h.invalidateCache(r, id)

	details := "service_edited" + identityPolicyChanges(*existing, params) +
		secretEnvChanges(existing.GoogleClientSecretEnv, params.GoogleClientSecretEnv, existing.MicrosoftClientSecretEnv, params.MicrosoftClientSecretEnv)
	if uploaded {
		details += " bg_image_uploaded=" + uploadedPath
	}
	auditOK := logAdminWrite(r.Context(), h.auditor, audit.Event{
		Type:      "service_edited",
		ServiceID: id,
		IP:        extractIP(r),
		UA:        r.UserAgent(),
		Details:   details,
		Success:   true,
	})
	http.Redirect(w, r, savedRedirect(cacheOK, auditOK), http.StatusSeeOther)
}

// handleBgImageUpload leser bg_image_upload fra multipart-skjema.
// Returnerer (uploaded bool, webPath string, errMsg string).
// webPath er på formen /filename.ext — klar til lagring i bg_image-kolonnen.
// Hvis ingen fil er lastet opp returneres (false, "", "").
// Hvis filen er ugyldig returneres (false, "", feilmelding).
func handleBgImageUpload(r *http.Request, svcID string) (bool, string, string) {
	file, header, err := r.FormFile("bg_image_upload")
	if err != nil {
		// Ingen fil valgt — ikke en feil.
		return false, "", ""
	}
	defer file.Close()

	if header.Size == 0 {
		return false, "", ""
	}
	if header.Size > 1<<20 {
		return false, "", "Bildet er for stort (maks 1 MB)."
	}

	// Valider MIME-type fra Content-Type-header på filfeltet.
	ct := header.Header.Get("Content-Type")
	mediaType, _, _ := mime.ParseMediaType(ct)
	var ext string
	switch mediaType {
	case "image/jpeg":
		ext = ".jpg"
	case "image/webp":
		ext = ".webp"
	case "image/png":
		ext = ".png"
	default:
		return false, "", fmt.Sprintf("Ugyldig filtype (%s). Kun JPEG, WebP og PNG er tillatt.", ct)
	}

	// Generer unikt filnavn: <service-id>-bg-<8 hex-tegn>.<ext>
	randBytes := make([]byte, 4)
	if _, rerr := rand.Read(randBytes); rerr != nil {
		return false, "", "Kunne ikke generere filnavn."
	}
	filename := svcID + "-bg-" + hex.EncodeToString(randBytes) + ext
	destPath := filepath.Join("static", filename)

	dest, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return false, "", "Kunne ikke lagre bildet: " + err.Error()
	}
	defer dest.Close()

	if _, err := io.Copy(dest, file); err != nil {
		_ = os.Remove(destPath)
		return false, "", "Kunne ikke lagre bildet."
	}

	return true, "/" + filename, ""
}

// buildCreateParams bygger CreateServiceParams fra HTTP-skjema-verdier.
func buildCreateParams(r *http.Request, id, now string) gen.CreateServiceParams {
	googleEnv, _ := formSecretEnv(r, "google_secret_env")
	microsoftEnv, _ := formSecretEnv(r, "microsoft_secret_env")
	return gen.CreateServiceParams{
		ID:                 id,
		DisplayName:        r.PostFormValue("display_name"),
		Tagline:            nullableStr(r.PostFormValue("tagline")),
		Domain:             r.PostFormValue("domain"),
		AuthHost:           nullableStr(r.PostFormValue("auth_host")),
		CallbackUrl:        r.PostFormValue("callback_url"),
		LogoHtml:           nullableStr(r.PostFormValue("logo_html")),
		BgImage:            nullableStr(r.PostFormValue("bg_image")),
		BgCss:              nullableStr(r.PostFormValue("bg_css")),
		Theme:              defaultStr(r.PostFormValue("theme"), "light"),
		AccentColor:        defaultStr(r.PostFormValue("accent_color"), "#2563EB"),
		EmailFromName:      defaultStr(r.PostFormValue("email_from_name"), id),
		EmailFromAddress:   nullableStr(r.PostFormValue("email_from_address")),
		AutoRegister:       checkboxInt(r, "auto_register"),
		DefaultRole:        nullableStr(r.PostFormValue("default_role")),
		DefaultOrg:         nullableStr(r.PostFormValue("default_org")),
		RequireRole:        nullableStr(r.PostFormValue("require_role")),
		EnforceOrg:         checkboxInt(r, "enforce_org"),
		IsDefault:          checkboxInt(r, "is_default"),
		AuthGoogle:         checkboxInt(r, "auth_google"),
		AuthMicrosoft:      checkboxInt(r, "auth_microsoft"),
		AuthMagicLink:      checkboxInt(r, "auth_magic_link"),
		AuthPassword:       checkboxInt(r, "auth_password"),
		JwtCookieName:      defaultStr(r.PostFormValue("jwt_cookie_name"), "auth_token"),
		AccessTokenTtl:     defaultStr(r.PostFormValue("access_token_ttl"), "PT15M"),
		RefreshTokenMaxAge: nullableStr(r.PostFormValue("refresh_token_max_age")),
		Active:             checkboxInt(r, "active"),
		UpdatedAt:          now,
		SubFormat:          formSubFormat(r),
		AutoLink:           formAutoLink(r),

		GoogleClientSecretEnv:    googleEnv,
		MicrosoftClientSecretEnv: microsoftEnv,
		// GitHub-feltene har ikke skjema før 019 F4: ny tjeneste starter av.
		AuthGithub: 0,
	}
}

// buildUpdateParams bygger UpdateServiceParams med den eksisterende raden som baseline.
// UpdateService skriver alle kolonner, så felt uten skjemainput (google_*, microsoft_*,
// logo_html, bg_css) må hentes fra raden — ellers nulles de ved hver lagring.
func buildUpdateParams(r *http.Request, existing gen.Service, now string) gen.UpdateServiceParams {
	cp := buildCreateParams(r, existing.ID, now)
	googleEnv, microsoftEnv := existing.GoogleClientSecretEnv, existing.MicrosoftClientSecretEnv
	if v, ok := formSecretEnv(r, "google_secret_env"); ok {
		googleEnv = v
	}
	if v, ok := formSecretEnv(r, "microsoft_secret_env"); ok {
		microsoftEnv = v
	}
	return gen.UpdateServiceParams{
		DisplayName:           cp.DisplayName,
		Tagline:               cp.Tagline,
		Domain:                cp.Domain,
		AuthHost:              cp.AuthHost,
		CallbackUrl:           cp.CallbackUrl,
		LogoHtml:              existing.LogoHtml,
		BgImage:               cp.BgImage,
		BgCss:                 existing.BgCss,
		Theme:                 cp.Theme,
		AccentColor:           cp.AccentColor,
		EmailFromName:         cp.EmailFromName,
		EmailFromAddress:      cp.EmailFromAddress,
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
		GoogleClientID:        existing.GoogleClientID,
		GoogleClientSecret:    existing.GoogleClientSecret,
		MicrosoftClientID:     existing.MicrosoftClientID,
		MicrosoftClientSecret: existing.MicrosoftClientSecret,
		// Mangler feltet i skjemaet beholdes lagret referanse; tomt felt gir NULL.
		GoogleClientSecretEnv:    googleEnv,
		MicrosoftClientSecretEnv: microsoftEnv,
		// Uten skjemafelt (F4) skal redigering aldri nulle GitHub-konfig.
		AuthGithub:            existing.AuthGithub,
		GithubClientID:        existing.GithubClientID,
		GithubClientSecretEnv: existing.GithubClientSecretEnv,
		JwtCookieName:         cp.JwtCookieName,
		AccessTokenTtl:        cp.AccessTokenTtl,
		RefreshTokenMaxAge:    cp.RefreshTokenMaxAge,
		Active:                cp.Active,
		UpdatedAt:             now,
		// Et skjema uten feltene (eldre side, skript) skal aldri endre dem: lagret verdi beholdes.
		SubFormat: valueOr(cp.SubFormat, existing.SubFormat),
		AutoLink:  valueOr(cp.AutoLink, existing.AutoLink),
		ID:        existing.ID,
	}
}

func valueOr[T any](p *T, fallback T) T {
	if p == nil {
		return fallback
	}
	return *p
}

// formSubFormat returnerer nil når feltet mangler i skjemaet. Verdien er validert av
// validateSubFormat før den når hit.
func formSubFormat(r *http.Request) *string {
	vals, ok := r.PostForm["sub_format"]
	if !ok || len(vals) == 0 {
		return nil
	}
	v := vals[len(vals)-1]
	return &v
}

// formAutoLink returnerer nil når feltet mangler. Malen sender et skjult 0 foran
// avkrysningen; nettleseren sender bare 1 i tillegg når boksen er krysset, så siste
// verdi gjelder. Uten det skjulte feltet kan «av» ikke skilles fra «feltet finnes ikke».
func formAutoLink(r *http.Request) *int64 {
	vals, ok := r.PostForm["auto_link"]
	if !ok || len(vals) == 0 {
		return nil
	}
	var v int64
	if vals[len(vals)-1] == "1" {
		v = 1
	}
	return &v
}

// validateSubFormat avviser alt annet enn email og id. Databasen har CHECK, men
// da ville admin fått en rå databasefeil i stedet for en forklaring.
func validateSubFormat(r *http.Request) error {
	v := formSubFormat(r)
	if v == nil {
		return nil
	}
	if *v != "email" && *v != "id" {
		return fmt.Errorf("Ugyldig sub-format. Velg email eller id.")
	}
	return nil
}

// identityPolicyChanges gir audit-details for endret sub_format/auto_link, siden begge
// er kontraktsendringer for klienten og må kunne spores til en actor.
func identityPolicyChanges(old gen.Service, p gen.UpdateServiceParams) string {
	var out string
	if old.SubFormat != p.SubFormat {
		out += " sub_format=" + old.SubFormat + "->" + p.SubFormat
	}
	if old.AutoLink != p.AutoLink {
		out += fmt.Sprintf(" auto_link=%d->%d", old.AutoLink, p.AutoLink)
	}
	return out
}

// findService henter en tjeneste uavhengig av active-flagget. GetServiceByID filtrerer
// på active = 1, og admin må kunne redigere (og reaktivere) deaktiverte tjenester.
func (h *ServicesHandler) findService(ctx context.Context, id string) (*gen.Service, error) {
	return findServiceByID(ctx, h.queries, id)
}

// findServiceByID er findService uten handler, delt med leverandørtilordningen.
// nil uten feil betyr at tjenesten ikke finnes.
func findServiceByID(ctx context.Context, q *gen.Queries, id string) (*gen.Service, error) {
	services, err := q.ListAllServices(ctx)
	if err != nil {
		return nil, err
	}
	for i := range services {
		if services[i].ID == id {
			return &services[i], nil
		}
	}
	return nil, nil
}

// Hjelpefunksjoner for skjemabehandling — delt mellom auth.go, users.go og services.go.

// 126 F2 (BACKLOG F19): auth_host konkateneres rått inn i magic-link-URL-en
// (resolveMagicLinkBaseURL i internal/auth/magic.go: "https://" + auth_host + "/magic-login/" + token).
// Ingen sjekk fantes tidligere — en feilkonfigurasjon (skrivefeil, skjema inkludert ved
// et uhell, eller en kompromittert konge-admin) kunne sende bearer-ekvivalente tokens
// til feil host i stedet for å feile trygt. Regexen er bevisst enkel (alfanumerisk +
// punktum + bindestrek) — dekker feilkonfigurasjon, ikke eksotisk-men-gyldige vertsnavn
// (internasjonaliserte domener). Tom streng er fortsatt gyldig (bruk global default).
var authHostPattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$`)

func validateAuthHost(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if strings.Contains(s, "://") {
		return fmt.Errorf("auth_host skal ikke inneholde skjema (fjern https://)")
	}
	if strings.ContainsAny(s, "/ \t\n") {
		return fmt.Errorf("auth_host skal være et rent vertsnavn, ikke inneholde sti eller mellomrom")
	}
	if !authHostPattern.MatchString(s) {
		return fmt.Errorf("auth_host er ikke et gyldig vertsnavn")
	}
	return nil
}

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
	if r.PostFormValue(name) == "1" {
		return 1
	}
	return 0
}

// validateEnforceOrg avviser enforce_org uten default_org. checkPolicy (internal/auth/google.go)
// krever DefaultOrg != nil, så kombinasjonen ville slått av org-håndhevingen uten varsel.
func validateEnforceOrg(r *http.Request) error {
	if checkboxInt(r, "enforce_org") == 1 && nullableStr(r.PostFormValue("default_org")) == nil {
		return fmt.Errorf("Krev org-samsvar (enforce_org) forutsetter en standard org. Fyll ut standard org eller fjern avkryssingen.")
	}
	return nil
}

// serviceFromForm bygger en gen.Service fra alle skjemafelt for feilrendering.
func serviceFromForm(r *http.Request) gen.Service {
	f := gen.Service{
		ID:                 r.PostFormValue("id"),
		DisplayName:        r.PostFormValue("display_name"),
		Tagline:            nullableStr(r.PostFormValue("tagline")),
		Domain:             r.PostFormValue("domain"),
		AuthHost:           nullableStr(r.PostFormValue("auth_host")),
		EmailFromName:      r.PostFormValue("email_from_name"),
		EmailFromAddress:   nullableStr(r.PostFormValue("email_from_address")),
		CallbackUrl:        r.PostFormValue("callback_url"),
		BgImage:            nullableStr(r.PostFormValue("bg_image")),
		AccentColor:        defaultStr(r.PostFormValue("accent_color"), "#2563EB"),
		Theme:              defaultStr(r.PostFormValue("theme"), "light"),
		JwtCookieName:      defaultStr(r.PostFormValue("jwt_cookie_name"), "auth_token"),
		AccessTokenTtl:     defaultStr(r.PostFormValue("access_token_ttl"), "PT15M"),
		RefreshTokenMaxAge: nullableStr(r.PostFormValue("refresh_token_max_age")),
		DefaultRole:        nullableStr(r.PostFormValue("default_role")),
		DefaultOrg:         nullableStr(r.PostFormValue("default_org")),
		RequireRole:        nullableStr(r.PostFormValue("require_role")),
		EnforceOrg:         checkboxInt(r, "enforce_org"),
		Active:             checkboxInt(r, "active"),
		AuthGoogle:         checkboxInt(r, "auth_google"),
		AuthMagicLink:      checkboxInt(r, "auth_magic_link"),
		AuthMicrosoft:      checkboxInt(r, "auth_microsoft"),
		AuthPassword:       checkboxInt(r, "auth_password"),
		IsDefault:          checkboxInt(r, "is_default"),
		AutoRegister:       checkboxInt(r, "auto_register"),
		SubFormat:          valueOr(formSubFormat(r), "email"),
		AutoLink:           valueOr(formAutoLink(r), 1),
	}
	f.GoogleClientSecretEnv, _ = formSecretEnv(r, "google_secret_env")
	f.MicrosoftClientSecretEnv, _ = formSecretEnv(r, "microsoft_secret_env")
	return f
}

// withoutSecrets nuller client id/secret i strukturen som går til malen, slik at et
// fremtidig malfelt ikke kan lekke dem. Skriving bruker den uavkortede raden.
func withoutSecrets(s gen.Service) gen.Service {
	s.GoogleClientID, s.GoogleClientSecret = nil, nil
	s.MicrosoftClientID, s.MicrosoftClientSecret = nil, nil
	return s
}

// overlayForm legger skjemaverdiene over den eksisterende raden, slik at feilsiden ved
// update beholder felt som ikke kommer fra skjemaet. Raden og dens id er autoritativ.
func overlayForm(existing gen.Service, r *http.Request) gen.Service {
	f := serviceFromForm(r)
	f.ID = existing.ID
	out := withoutSecrets(existing)
	out.DisplayName, out.Tagline, out.Domain, out.AuthHost = f.DisplayName, f.Tagline, f.Domain, f.AuthHost
	out.EmailFromName, out.EmailFromAddress, out.CallbackUrl, out.BgImage = f.EmailFromName, f.EmailFromAddress, f.CallbackUrl, f.BgImage
	out.AccentColor, out.Theme, out.JwtCookieName = f.AccentColor, f.Theme, f.JwtCookieName
	out.AccessTokenTtl, out.RefreshTokenMaxAge = f.AccessTokenTtl, f.RefreshTokenMaxAge
	out.DefaultRole, out.DefaultOrg, out.RequireRole, out.EnforceOrg = f.DefaultRole, f.DefaultOrg, f.RequireRole, f.EnforceOrg
	out.Active, out.AuthGoogle, out.AuthMagicLink, out.AuthMicrosoft = f.Active, f.AuthGoogle, f.AuthMagicLink, f.AuthMicrosoft
	out.AuthPassword, out.IsDefault, out.AutoRegister = f.AuthPassword, f.IsDefault, f.AutoRegister
	// Ugyldig verdi vises aldri tilbake: feilsiden viser det som faktisk er lagret.
	out.SubFormat = existing.SubFormat
	if v := formSubFormat(r); v != nil && (*v == "email" || *v == "id") {
		out.SubFormat = *v
	}
	out.AutoLink = valueOr(formAutoLink(r), existing.AutoLink)
	if _, ok := formSecretEnv(r, "google_secret_env"); ok {
		out.GoogleClientSecretEnv = f.GoogleClientSecretEnv
	}
	if _, ok := formSecretEnv(r, "microsoft_secret_env"); ok {
		out.MicrosoftClientSecretEnv = f.MicrosoftClientSecretEnv
	}
	return out
}

// renderServiceError viser skjemaet på nytt med 422. existing er nil ved opprettelse.
func (h *ServicesHandler) renderServiceError(w http.ResponseWriter, svc gen.Service, existing *gen.Service, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnprocessableEntity)
	data := map[string]interface{}{
		"IsNew":   existing == nil,
		"Service": svc,
		"Error":   errMsg,
	}
	h.addSecretStatus(data, svc, existing)
	_ = h.editTpl.Execute(w, data)
}

// addSecretStatus legger til hva malen trenger om klienthemmeligheter: om env-
// referansen er satt og om raden fortsatt har klartekst. Aldri verdiene.
func (h *ServicesHandler) addSecretStatus(data map[string]interface{}, shown gen.Service, stored *gen.Service) {
	data["GoogleEnvSet"] = h.envIsSet(shown.GoogleClientSecretEnv)
	data["MicrosoftEnvSet"] = h.envIsSet(shown.MicrosoftClientSecretEnv)
	data["GooglePlain"] = stored != nil && stored.GoogleClientSecret != nil && *stored.GoogleClientSecret != ""
	data["MicrosoftPlain"] = stored != nil && stored.MicrosoftClientSecret != nil && *stored.MicrosoftClientSecret != ""
}

func (h *ServicesHandler) envIsSet(name *string) bool {
	if name == nil || !service.ClientSecretEnvRe.MatchString(*name) {
		return false
	}
	return strings.TrimSpace(h.getenv(*name)) != ""
}

// formSecretEnv returnerer (nil, false) når feltet mangler i skjemaet, slik at en
// eldre side eller et skript ikke endrer lagret referanse. Tomt felt gir NULL.
func formSecretEnv(r *http.Request, field string) (*string, bool) {
	vals, ok := r.PostForm[field]
	if !ok || len(vals) == 0 {
		return nil, false
	}
	return nullableStr(vals[len(vals)-1]), true
}

// validateSecretEnv avviser navn utenfor KAUTH_SVC_-prefikset, slik at admin ikke kan
// peke en tjeneste mot KAUTH_PRIVATE_KEY_PEM eller andre variabler.
func validateSecretEnv(r *http.Request) error {
	for _, f := range []struct{ field, label string }{
		{"google_secret_env", "Google"},
		{"microsoft_secret_env", "Microsoft"},
	} {
		v, ok := formSecretEnv(r, f.field)
		if ok && v != nil && (len(*v) > 64 || !service.ClientSecretEnvRe.MatchString(*v)) {
			return fmt.Errorf("%s: miljøvariabelen må hete KAUTH_SVC_ etterfulgt av store bokstaver, tall og understrek (maks 64 tegn).", f.label)
		}
	}
	return nil
}

// secretEnvChanges gir audit-details for endret env-referanse. Bare navn, aldri verdier.
func secretEnvChanges(oldG, newG, oldM, newM *string) string {
	dash := func(p *string) string {
		if p == nil {
			return "(ingen)"
		}
		return *p
	}
	var out string
	if dash(oldG) != dash(newG) {
		out += " google_secret_env=" + dash(oldG) + "->" + dash(newG)
	}
	if dash(oldM) != dash(newM) {
		out += " microsoft_secret_env=" + dash(oldM) + "->" + dash(newM)
	}
	return out
}
