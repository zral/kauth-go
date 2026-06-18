package admin

import (
	"encoding/csv"
	"html/template"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/zral/kauth-go/internal/db/gen"
)

const auditPerPage = 50

// AuditHandler håndterer visning og eksport av auditlogg.
type AuditHandler struct {
	queries *gen.Queries
	listTpl *template.Template
}

func NewAuditHandler(queries *gen.Queries) *AuditHandler {
	tpl := template.Must(template.ParseFiles("templates/admin/audit.html"))
	return &AuditHandler{queries: queries, listTpl: tpl}
}

// HandleList rendrer auditlogg-tabellen med filtrering og paginering.
func (h *AuditHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	email := strings.TrimSpace(r.URL.Query().Get("email"))
	serviceFilter := strings.TrimSpace(r.URL.Query().Get("service"))
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	offset := int64((page - 1) * auditPerPage)

	var events []gen.AuditEvent
	var err error

	switch {
	case email != "":
		events, err = h.queries.ListAuditEventsByEmail(ctx, gen.ListAuditEventsByEmailParams{
			Email:  &email,
			Limit:  auditPerPage,
			Offset: offset,
		})
	case serviceFilter != "":
		events, err = h.queries.ListAuditEventsByService(ctx, gen.ListAuditEventsByServiceParams{
			ServiceID: &serviceFilter,
			Limit:     auditPerPage,
			Offset:    offset,
		})
	default:
		events, err = h.queries.ListAuditEvents(ctx, gen.ListAuditEventsParams{
			Limit:  auditPerPage,
			Offset: offset,
		})
	}
	if err != nil {
		http.Error(w, "databasefeil: "+err.Error(), http.StatusInternalServerError)
		return
	}

	total, _ := h.queries.CountAuditEvents(ctx)
	totalPages := int(math.Ceil(float64(total) / float64(auditPerPage)))
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
		Events        []gen.AuditEvent
		Email         string
		ServiceFilter string
		Page          int
		TotalPages    int
		PrevPage      int
		NextPage      int
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.listTpl.Execute(w, pageData{
		Events: events, Email: email, ServiceFilter: serviceFilter,
		Page: page, TotalPages: totalPages,
		PrevPage: prevPage, NextPage: nextPage,
	})
}

// HandleExport skriver auditlogg som CSV med csvEsc på alle felt.
func (h *AuditHandler) HandleExport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	email := strings.TrimSpace(r.URL.Query().Get("email"))
	serviceFilter := strings.TrimSpace(r.URL.Query().Get("service"))

	var events []gen.AuditEvent
	var err error

	switch {
	case email != "":
		events, err = h.queries.ListAuditEventsByEmail(ctx, gen.ListAuditEventsByEmailParams{
			Email:  &email,
			Limit:  100000,
			Offset: 0,
		})
	case serviceFilter != "":
		events, err = h.queries.ListAuditEventsByService(ctx, gen.ListAuditEventsByServiceParams{
			ServiceID: &serviceFilter,
			Limit:     100000,
			Offset:    0,
		})
	default:
		events, err = h.queries.ListAuditEvents(ctx, gen.ListAuditEventsParams{
			Limit:  100000,
			Offset: 0,
		})
	}
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
