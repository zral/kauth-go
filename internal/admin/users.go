package admin

import (
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"modernc.org/sqlite"

	"github.com/go-chi/chi/v5"
	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

const usersPerPage = 25

// UsersHandler håndterer alle bruker-CRUD-ruter i admin-panelet.
type UsersHandler struct {
	queries *gen.Queries
	// sqlDB trengs for transaksjonene i frakobling og e-postendring; queries
	// alene kan ikke samle flere skrivinger i én commit.
	sqlDB   *sql.DB
	auditor auditLogger
	listTpl *template.Template
	editTpl *template.Template
}

func NewUsersHandler(queries *gen.Queries, sqlDB *sql.DB, auditor auditLogger) *UsersHandler {
	listTpl := template.Must(template.ParseFiles("templates/admin/users.html"))
	editTpl := template.Must(template.ParseFiles("templates/admin/user-edit.html"))
	return &UsersHandler{
		queries: queries,
		sqlDB:   sqlDB,
		auditor: auditor,
		listTpl: listTpl,
		editTpl: editTpl,
	}
}

func usersRedirect(auditOK bool) string {
	if auditOK {
		return "/admin/users"
	}
	return redirectWithWarns("/admin/users", "audit")
}

// HandleList rendrer bruker-tabellen med paginering og filtrering.
func (h *UsersHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	org := strings.TrimSpace(r.URL.Query().Get("org"))
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	var users []gen.User
	var total int64

	if search != "" || org != "" {
		// Hent stor window, filtrer i Go, paginer det filtrerte resultatet.
		var all []gen.User
		var err error
		if org != "" {
			all, err = h.queries.ListUsersByOrg(ctx, gen.ListUsersByOrgParams{
				Orgs:   "%" + org + "%",
				Limit:  1000,
				Offset: 0,
			})
		} else {
			all, err = h.queries.ListUsers(ctx, gen.ListUsersParams{
				Limit:  1000,
				Offset: 0,
			})
		}
		if err != nil {
			http.Error(w, "databasefeil: "+err.Error(), http.StatusInternalServerError)
			return
		}

		needle := strings.ToLower(search)
		var filtered []gen.User
		for _, u := range all {
			if needle != "" && !strings.Contains(strings.ToLower(u.Email), needle) {
				continue
			}
			filtered = append(filtered, u)
		}
		total = int64(len(filtered))
		start := (page - 1) * usersPerPage
		end := start + usersPerPage
		if start > len(filtered) {
			start = len(filtered)
		}
		if end > len(filtered) {
			end = len(filtered)
		}
		users = filtered[start:end]
	} else {
		offset := int64((page - 1) * usersPerPage)
		var err error
		users, err = h.queries.ListUsers(ctx, gen.ListUsersParams{
			Limit:  usersPerPage,
			Offset: offset,
		})
		if err != nil {
			http.Error(w, "databasefeil: "+err.Error(), http.StatusInternalServerError)
			return
		}
		total, err = h.queries.CountUsers(ctx)
		if err != nil {
			http.Error(w, "databasefeil: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	totalPages := int(math.Ceil(float64(total) / float64(usersPerPage)))
	if totalPages < 1 {
		totalPages = 1
	}

	var prevPage, nextPage int
	if page > 1 {
		prevPage = page - 1
	}
	if page < totalPages {
		nextPage = page + 1
	}

	type pageData struct {
		Users      []gen.User
		Search     string
		Org        string
		Page       int
		TotalPages int
		PrevPage   int
		NextPage   int
		WarnAudit  bool
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.listTpl.Execute(w, pageData{
		Users: users, Search: search, Org: org,
		Page: page, TotalPages: totalPages,
		PrevPage: prevPage, NextPage: nextPage,
		WarnAudit: warnFlags(r, "audit")["audit"],
	})
}

// HandleNew rendrer skjema for ny bruker.
func (h *UsersHandler) HandleNew(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.editTpl.Execute(w, map[string]interface{}{
		"IsNew": true,
		"User":  gen.User{},
	})
}

// HandleCreate oppretter ny bruker fra POST-skjema.
func (h *UsersHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	email := strings.TrimSpace(strings.ToLower(r.PostFormValue("email")))
	password := r.PostFormValue("password")
	name := strings.TrimSpace(r.PostFormValue("name"))
	roles := strings.TrimSpace(r.PostFormValue("roles"))
	orgs := strings.TrimSpace(r.PostFormValue("orgs"))

	if email == "" {
		h.renderEditError(w, gen.User{Roles: roles, Orgs: orgs}, true, email, "E-post er påkrevd.")
		return
	}

	var passwordHash *string
	if password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			h.renderEditError(w, gen.User{}, true, email, "Feil ved hashing av passord.")
			return
		}
		hs := string(hash)
		passwordHash = &hs
	}

	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	var namePtr *string
	if name != "" {
		namePtr = &name
	}

	publicID, err := token.NewPublicID()
	if err != nil {
		slog.Error("admin: kunne ikke lage public_id", "err", err)
		h.renderEditError(w, gen.User{Roles: roles, Orgs: orgs}, true, email, "Intern feil ved opprettelse.")
		return
	}
	_, err = h.queries.CreateUser(r.Context(), gen.CreateUserParams{
		PublicID:     publicID,
		Email:        email,
		PasswordHash: passwordHash,
		Name:         namePtr,
		Roles:        roles,
		Orgs:         orgs,
		CreatedAt:    now,
	})
	if err != nil {
		slog.Error("admin: opprettelse av bruker feilet", "err", err)
		msg := "Feil ved opprettelse."
		var se *sqlite.Error
		if errors.As(err, &se) && (se.Code() == 2067 || se.Code() == 1555) { // UNIQUE / PRIMARYKEY
			msg = "Feil ved opprettelse: finnes e-posten allerede?"
		}
		h.renderEditError(w, gen.User{Roles: roles, Orgs: orgs}, true, email, msg)
		return
	}

	auditOK := logAdminWrite(r.Context(), h.auditor, audit.Event{
		Type:    "user_created",
		Email:   email,
		IP:      extractIP(r),
		UA:      r.UserAgent(),
		Success: true,
	})
	http.Redirect(w, r, usersRedirect(auditOK), http.StatusSeeOther)
}

// HandleEdit rendrer redigeringsskjema for eksisterende bruker.
func (h *UsersHandler) HandleEdit(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	found, err := h.queries.GetUserByID(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "databasefeil", http.StatusInternalServerError)
		return
	}
	data, err := h.editData(r.Context(), found)
	if err != nil {
		http.Error(w, "databasefeil", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.editTpl.Execute(w, data)
}

// editData bygger malen for en eksisterende bruker. Både HandleEdit og
// feilsidene bruker den, slik at identitetene og bundet-markøren ikke
// forsvinner når en skjemafeil rendrer siden på nytt.
func (h *UsersHandler) editData(ctx context.Context, u gen.User) (map[string]interface{}, error) {
	idns, err := h.queries.ListIdentitiesByUser(ctx, u.ID)
	if err != nil {
		return nil, fmt.Errorf("list identiteter: %w", err)
	}
	names, err := h.queries.ListIdentityProviderNames(ctx)
	if err != nil {
		return nil, fmt.Errorf("list leverandørnavn: %w", err)
	}
	views := identityViews(idns, names)
	hasAdminIdentity := false
	for _, v := range views {
		if v.AdminOK {
			hasAdminIdentity = true
		}
	}
	boundAt := ""
	if u.AdminBoundAt != nil {
		boundAt = *u.AdminBoundAt
	}
	return map[string]interface{}{
		"IsNew":          false,
		"User":           u,
		"Identities":     views,
		"ShowIdentities": true,
		"AdminBoundAt":   boundAt,
		// Bundet uten noen admin_ok-identitet: ny admin-konto krever driftsprosedyren.
		"BoundWithoutIdentity": boundAt != "" && !hasAdminIdentity,
	}, nil
}

// identityView er det admin ser om en koblet identitet. Subject avkortes: det er
// leverandørens stabile id for personen og trengs ikke i fulltekst for å skille kontoer.
type identityView struct {
	ID                                                  int64
	Provider, Tenant, Subject, Email, Created, LastUsed string
	AdminOK                                             bool
	Unknown                                             bool
}

const msIssuerPrefix = "https://login.microsoftonline.com/"

// identityViews gir visningsnavn for oidc-identiteter ved oppslag på issuer. En
// identitet hvis leverandørrad er borte vises som ukjent, med issuer, så admin ser
// hva den hører til uten å gjette.
func identityViews(in []gen.UserIdentity, names []gen.ListIdentityProviderNamesRow) []identityView {
	byIssuer := make(map[string]gen.ListIdentityProviderNamesRow, len(names))
	for _, n := range names {
		byIssuer[n.Issuer] = n
	}
	out := make([]identityView, 0, len(in))
	for _, i := range in {
		v := identityView{
			ID:       i.ID,
			Provider: i.Provider,
			Tenant:   "—",
			Subject:  shortSubject(i.Subject),
			Email:    "—",
			Created:  i.CreatedAt,
			LastUsed: "—",
			AdminOK:  i.AdminOk == 1,
		}
		if i.Provider == "oidc" {
			if n, ok := byIssuer[i.Issuer]; ok {
				v.Provider = n.DisplayName + " (" + n.Slug + ")"
			} else {
				v.Provider, v.Unknown = "ukjent leverandør", true
				v.Tenant = i.Issuer
			}
		}
		if i.Provider == "microsoft" && strings.HasPrefix(i.Issuer, msIssuerPrefix) {
			if tid, _, ok := strings.Cut(strings.TrimPrefix(i.Issuer, msIssuerPrefix), "/"); ok && tid != "" {
				v.Tenant = tid
			}
		}
		if i.Email != nil && *i.Email != "" {
			v.Email = *i.Email
		}
		if i.LastUsedAt != nil && *i.LastUsedAt != "" {
			v.LastUsed = *i.LastUsedAt
		}
		out = append(out, v)
	}
	return out
}

func shortSubject(s string) string {
	r := []rune(s)
	if len(r) <= 6 {
		return string(r)
	}
	return string(r[:6]) + "…"
}

// HandleUpdate lagrer endringer på eksisterende bruker.
func (h *UsersHandler) HandleUpdate(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	_ = r.ParseForm()
	name := strings.TrimSpace(r.PostFormValue("name"))
	roles := strings.TrimSpace(r.PostFormValue("roles"))
	orgs := strings.TrimSpace(r.PostFormValue("orgs"))

	var namePtr *string
	if name != "" {
		namePtr = &name
	}

	err = h.queries.UpdateUser(r.Context(), gen.UpdateUserParams{
		Name:  namePtr,
		Roles: roles,
		Orgs:  orgs,
		ID:    id,
	})
	if err != nil {
		http.Error(w, "databasefeil: "+err.Error(), http.StatusInternalServerError)
		return
	}

	auditOK := logAdminWrite(r.Context(), h.auditor, audit.Event{
		Type:    "user_edited",
		IP:      extractIP(r),
		UA:      r.UserAgent(),
		Success: true,
		Details: fmt.Sprintf("id=%d", id),
	})
	http.Redirect(w, r, usersRedirect(auditOK), http.StatusSeeOther)
}

// HandleDeactivate deaktiverer en bruker.
func (h *UsersHandler) HandleDeactivate(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	// E-posten kommer fra brukerraden (RETURNING), ikke fra URL/skjema, og
	// brukes bare i auditraden. Revokeringen går på user_id (D8a).
	email, err := h.queries.DeactivateUser(r.Context(), gen.DeactivateUserParams{
		DeactivatedAt: &now,
		ID:            id,
	})
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		slog.Error("admin: deaktivering feilet", "id", id, "err", err)
		http.Error(w, "databasefeil", http.StatusInternalServerError)
		return
	}

	// WithoutCancel: revokeringen og auditraden skal fullføres selv om admin kobler fra.
	// Feiler den, står deaktiveringen; refresh for en deaktivert bruker avvises
	// uansett (refresh_user_inactive).
	ctx := context.WithoutCancel(r.Context())
	reason := "user_deactivated"
	var details string
	revoked, err := h.queries.RevokeUserRefreshTokens(ctx, gen.RevokeUserRefreshTokensParams{
		RevokedReason: &reason,
		UserID:        &id,
	})
	if err != nil {
		slog.Error("admin: revokering av refresh-tokens etter deaktivering feilet", "id", id, "err", err)
		details = fmt.Sprintf("id=%d revoke_failed", id)
	} else {
		details = fmt.Sprintf("id=%d revoked=%d", id, revoked)
	}

	auditOK := logAdminWrite(ctx, h.auditor, audit.Event{
		Type:    "user_deactivated",
		Email:   email,
		IP:      extractIP(r),
		UA:      r.UserAgent(),
		Success: true,
		Details: details,
	})
	http.Redirect(w, r, usersRedirect(auditOK), http.StatusSeeOther)
}

// HandleExport skriver alle brukere som CSV.
// ALDRI password_hash i eksporten.
func (h *UsersHandler) HandleExport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	users, err := h.queries.ListUsers(ctx, gen.ListUsersParams{Limit: 100000, Offset: 0})
	if err != nil {
		http.Error(w, "databasefeil: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="kauth-users.csv"`)

	wr := csv.NewWriter(w)
	_ = wr.Write([]string{"id", "email", "name", "roles", "orgs", "created_at", "last_login"})

	for _, u := range users {
		name := ""
		if u.Name != nil {
			name = *u.Name
		}
		lastLogin := ""
		if u.LastLogin != nil {
			lastLogin = *u.LastLogin
		}
		_ = wr.Write([]string{
			csvEsc(strconv.FormatInt(u.ID, 10)),
			csvEsc(u.Email),
			csvEsc(name),
			csvEsc(u.Roles),
			csvEsc(u.Orgs),
			csvEsc(u.CreatedAt),
			csvEsc(lastLogin),
		})
	}
	wr.Flush()
}

// csvEsc beskytter mot CSV-injeksjon (formelinjeksjon).
// Quoting av felt med komma/anførselstegn/newline håndteres av csv.NewWriter.
func csvEsc(s string) string {
	if len(s) == 0 {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

func (h *UsersHandler) renderEditError(w http.ResponseWriter, user gen.User, isNew bool, formEmail, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnprocessableEntity)
	_ = h.editTpl.Execute(w, map[string]interface{}{
		"IsNew":     isNew,
		"User":      user,
		"FormEmail": formEmail,
		"Error":     errMsg,
	})
}
