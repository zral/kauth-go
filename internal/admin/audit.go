package admin

import (
	"database/sql"
	"encoding/csv"
	"html/template"
	"math"
	"net/http"
	"strconv"

	"github.com/zral/kauth-go/internal/db/gen"
)

const (
	auditPerPage     = 50
	auditExportLimit = 100000
)

// AuditHandler håndterer visning og eksport av auditlogg.
type AuditHandler struct {
	sqldb   *sql.DB
	listTpl *template.Template
}

// auditTplFuncs gjør sentinel-verdier lesbare i skjemaet.
var auditTplFuncs = template.FuncMap{
	"auditLabel": func(v string) string {
		if v == auditNoneValue {
			return "(ingen)"
		}
		return v
	},
}

func NewAuditHandler(sqldb *sql.DB) *AuditHandler {
	tpl := template.Must(template.New("audit.html").
		Funcs(auditTplFuncs).
		ParseFiles("templates/admin/audit.html"))
	return &AuditHandler{sqldb: sqldb, listTpl: tpl}
}

// HandleList rendrer auditlogg-tabellen med filtrering og paginering.
func (h *AuditHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	filter := parseAuditFilter(r)

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	total, err := countAuditEvents(ctx, h.sqldb, filter)
	if err != nil {
		http.Error(w, "databasefeil: "+err.Error(), http.StatusInternalServerError)
		return
	}
	totalPages := int(math.Ceil(float64(total) / float64(auditPerPage)))
	if totalPages < 1 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}

	events, err := queryAuditEvents(ctx, h.sqldb, filter, auditPerPage, int64((page-1)*auditPerPage))
	if err != nil {
		http.Error(w, "databasefeil: "+err.Error(), http.StatusInternalServerError)
		return
	}

	choices, err := loadAuditChoices(ctx, h.sqldb)
	if err != nil {
		http.Error(w, "databasefeil: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var prevPage, nextPage int
	if page > 1 {
		prevPage = page - 1
	}
	if page < totalPages {
		nextPage = page + 1
	}

	type pageData struct {
		Events     []gen.AuditEvent
		Filter     auditFilter
		Choices    auditChoices
		ExportURL  string
		PrevURL    string
		NextURL    string
		Total      int64
		Page       int
		TotalPages int
	}

	// URL-ene bygges her, ikke i templaten — html/template ville escapet
	// querystrengen som én parameterverdi og ødelagt den.
	qs := filter.QueryString()
	data := pageData{
		Events: events, Filter: filter, Choices: choices,
		ExportURL: "/admin/audit/export?" + qs, Total: total,
		Page: page, TotalPages: totalPages,
	}
	if prevPage > 0 {
		data.PrevURL = "/admin/audit?" + qs + "&page=" + strconv.Itoa(prevPage)
	}
	if nextPage > 0 {
		data.NextURL = "/admin/audit?" + qs + "&page=" + strconv.Itoa(nextPage)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.listTpl.Execute(w, data)
}

// HandleExport skriver auditlogg som CSV med samme filter som listevisningen.
func (h *AuditHandler) HandleExport(w http.ResponseWriter, r *http.Request) {
	events, err := queryAuditEvents(r.Context(), h.sqldb, parseAuditFilter(r), auditExportLimit, 0)
	if err != nil {
		http.Error(w, "databasefeil: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="kauth-audit.csv"`)

	wr := csv.NewWriter(w)
	_ = wr.Write([]string{
		"id", "created_at", "event_type", "auth_method",
		"email", "service_id", "ip_address", "user_agent", "success", "details",
	})

	for _, e := range events {
		row := []string{
			csvEsc(strconv.FormatInt(e.ID, 10)),
			csvEsc(e.CreatedAt),
			csvEsc(e.EventType),
			csvEsc(derefStr(e.AuthMethod)),
			csvEsc(derefStr(e.Email)),
			csvEsc(derefStr(e.ServiceID)),
			csvEsc(derefStr(e.IpAddress)),
			csvEsc(derefStr(e.UserAgent)),
			csvEsc(strconv.FormatInt(e.Success, 10)),
			csvEsc(derefStr(e.Details)),
		}
		_ = wr.Write(row)
	}
	wr.Flush()
}

// derefStr konverterer *string til string, returnerer "" for nil.
func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
