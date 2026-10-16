package admin

import (
	"database/sql"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/idp"
)

// ProvidersHandler viser identitetsleverandørene og lagrer hvilke som er
// tilordnet hver tjeneste. Leverandørradene selv (issuer, klient, hemmelighet)
// opprettes og endres aldri her; det følger driftsprosedyren med omstart.
type ProvidersHandler struct {
	queries *gen.Queries
	sqlDB   *sql.DB
	idps    *idp.Registry
	auditor auditLogger
	tpl     *template.Template
}

func NewProvidersHandler(queries *gen.Queries, sqlDB *sql.DB, idps *idp.Registry, auditor auditLogger) *ProvidersHandler {
	return &ProvidersHandler{
		queries: queries,
		sqlDB:   sqlDB,
		idps:    idps,
		auditor: auditor,
		tpl:     template.Must(template.ParseFiles("templates/admin/providers.html")),
	}
}

type providerServiceRef struct {
	ServiceID string
	Position  int64
}

type providerView struct {
	idp.Status
	Services []providerServiceRef
}

// HandleList er en lesende oversikt. Statusene er et øyeblikksbilde fra siste
// omstart, mens tilordningene leses fra databasen; siden sier det eksplisitt.
func (h *ProvidersHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	assigns, err := h.queries.ListServiceIdentityProvidersAll(r.Context())
	if err != nil {
		slog.Error("admin: les leverandørtilordninger feilet", "error", err)
		http.Error(w, "databasefeil", http.StatusInternalServerError)
		return
	}
	byProvider := map[int64][]providerServiceRef{}
	for _, a := range assigns {
		byProvider[a.ProviderID] = append(byProvider[a.ProviderID], providerServiceRef{ServiceID: a.ServiceID, Position: a.Position})
	}
	statuses := h.idps.Statuses()
	views := make([]providerView, 0, len(statuses))
	for _, s := range statuses {
		views = append(views, providerView{Status: s, Services: byProvider[s.ID]})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.tpl.Execute(w, map[string]interface{}{"Providers": views})
}

// serviceProviderRow er en lastet leverandør i tilordningsskjemaet på tjenestesiden.
type serviceProviderRow struct {
	ID          int64
	Slug        string
	DisplayName string
	Assigned    bool
	Position    int64
}

// keptProviderRow er en tilordning til en leverandør som ikke er lastet. Den vises
// skrivebeskyttet og kan bare fjernes, ikke endres.
type keptProviderRow struct {
	ID          int64
	Slug        string
	DisplayName string
	Position    int64
	Reason      string
	Inactive    bool
}

// serviceRows gir én rad per lastet leverandør, med dagens tilordning forhåndsutfylt.
// Ikke-lastede leverandører kan ikke tilordnes og vises ikke her.
func (h *ProvidersHandler) serviceRows(r *http.Request, serviceID string) ([]serviceProviderRow, []keptProviderRow, error) {
	assigns, err := h.queries.ListAssignmentsForService(r.Context(), serviceID)
	if err != nil {
		return nil, nil, err
	}
	pos := map[int64]int64{}
	for _, a := range assigns {
		pos[a.ProviderID] = a.Position
	}
	var rows []serviceProviderRow
	var kept []keptProviderRow
	for _, s := range h.idps.Statuses() {
		if !s.Loaded {
			if p, assigned := pos[s.ID]; assigned {
				kept = append(kept, keptProviderRow{ID: s.ID, Slug: s.Slug, DisplayName: s.DisplayName, Position: p, Reason: s.Reason, Inactive: !s.Active})
			}
			continue
		}
		p, assigned := pos[s.ID]
		rows = append(rows, serviceProviderRow{ID: s.ID, Slug: s.Slug, DisplayName: s.DisplayName, Assigned: assigned, Position: p})
	}
	return rows, kept, nil
}

func idKey(prefix string, id int64) string { return prefix + strconv.FormatInt(id, 10) }
