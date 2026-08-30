package admin

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
)

// renderAudit kjører HandleList mot den seedede test-basen og returnerer HTML.
func renderAudit(t *testing.T, query string) string {
	t.Helper()
	sqldb := setupAuditDB(t)
	t.Chdir("../..") // templates/ ligger relativt til prosjektroten

	h := NewAuditHandler(sqldb)
	w := httptest.NewRecorder()
	h.HandleList(w, httptest.NewRequest(http.MethodGet, "/admin/audit"+query, nil))

	require.Equal(t, http.StatusOK, w.Code)
	return w.Body.String()
}

func TestHandleList_RendersCompleteTemplate(t *testing.T) {
	// Execute-feil svelges av handleren — sluttmerkelappen beviser at
	// hele templaten ble rendret uten å stoppe midtveis.
	body := renderAudit(t, "")
	assert.Contains(t, body, "</html>")
	assert.Contains(t, body, "lars@spekto.no")
}

func TestHandleList_RendersChoicesFromData(t *testing.T) {
	body := renderAudit(t, "")
	assert.Contains(t, body, `name="event" value="refresh_token_issued"`)
	assert.Contains(t, body, `name="method" value="password"`)
	assert.Contains(t, body, `name="service" value="spekto"`)
	assert.Contains(t, body, "(ingen)") // sentinel for rader uten metode/tjeneste
}

func TestHandleList_NoFilter_AllCheckboxesChecked(t *testing.T) {
	body := renderAudit(t, "")
	assert.Contains(t, body, `name="event" value="login_failed" checked`)
	assert.Contains(t, body, `name="ok" value="0" checked`)
}

func TestHandleList_FilteredGroup_OnlySelectedIsChecked(t *testing.T) {
	body := renderAudit(t, "?event=login_failed")
	assert.Contains(t, body, `name="event" value="login_failed" checked`)
	assert.Contains(t, body, `name="event" value="login_success">`)
}

func TestHandleList_AppliesFilterToRows(t *testing.T) {
	body := renderAudit(t, "?email=%40pov.no")
	assert.Contains(t, body, "kari@pov.no")
	assert.NotContains(t, body, "lars@spekto.no")
	assert.Contains(t, body, "2 treff")
}

func TestHandleList_NoMatches_ShowsEmptyRow(t *testing.T) {
	body := renderAudit(t, "?email=finnesikke")
	assert.Contains(t, body, "Ingen hendelser matcher filteret.")
	assert.Contains(t, body, "0 treff")
}

func TestHandleList_ExportLinkCarriesAllFilterValues(t *testing.T) {
	body := renderAudit(t, "?event=login_success&event=login_failed&ok=1")
	// &amp; er korrekt HTML-escaping av & i href.
	assert.Contains(t, body,
		"/admin/audit/export?event=login_success&amp;event=login_failed&amp;ok=1")
}

func TestHandleList_PaginationLinkKeepsFilter(t *testing.T) {
	ctx := context.Background()
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })

	str := func(s string) *string { return &s }
	for i := range auditPerPage + 5 {
		require.NoError(t, q.InsertAuditEvent(ctx, gen.InsertAuditEventParams{
			EventType: "login_success", Email: str("lars@spekto.no"), Success: 1,
			CreatedAt: fmt.Sprintf("2026-08-%02dT10:00:00Z", i%28+1),
		}))
	}

	t.Chdir("../..")
	h := NewAuditHandler(sqldb)
	w := httptest.NewRecorder()
	h.HandleList(w, httptest.NewRequest(http.MethodGet, "/admin/audit?email=spekto", nil))

	body := w.Body.String()
	assert.Contains(t, body, "/admin/audit?email=spekto&amp;page=2")
	assert.Contains(t, body, "Side 1 av 2")
	assert.Contains(t, body, "55 treff")
}

func TestHandleExport_FilteredCSVSkipsNonMatchingRows(t *testing.T) {
	sqldb := setupAuditDB(t)
	h := &AuditHandler{sqldb: sqldb}

	w := httptest.NewRecorder()
	h.HandleExport(w, httptest.NewRequest(http.MethodGet, "/admin/audit/export?ok=0", nil))

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/csv; charset=utf-8", w.Header().Get("Content-Type"))
	body := w.Body.String()
	assert.Contains(t, body, "login_failed")
	assert.NotContains(t, body, "refresh_token_issued")
}
