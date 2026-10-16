package admin

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
)

// reloadFailDB lar bare omlastingens tilordningsspørring feile, slik at lagringen
// går gjennom mens ReloadAssignments gir feil.
type reloadFailDB struct{ gen.DBTX }

func (d reloadFailDB) QueryContext(ctx context.Context, q string, a ...interface{}) (*sql.Rows, error) {
	if strings.Contains(q, "-- name: ListServiceIdentityProviders :many") {
		return nil, errors.New("simulert feil")
	}
	return d.DBTX.QueryContext(ctx, q, a...)
}

func (d reloadFailDB) PrepareContext(ctx context.Context, q string) (*sql.Stmt, error) {
	if strings.Contains(q, "-- name: ListServiceIdentityProviders :many") {
		return nil, errors.New("simulert feil")
	}
	return d.DBTX.PrepareContext(ctx, q)
}

func provRouter(ph *ProvidersHandler, sh *ServicesHandler) http.Handler {
	r := chi.NewRouter()
	r.Use(withActor)
	r.Get("/admin/services/{id}/edit", sh.HandleEdit)
	r.Post("/admin/services/{id}/providers", ph.HandleServiceUpdate)
	return r
}

func TestServiceProviders_ReloadFailure_SavedButWarned(t *testing.T) {
	e := newProvEnv(t)
	ph := NewProvidersHandler(gen.New(reloadFailDB{e.sqldb}), e.sqldb, e.idps, audit.NewService(e.q))
	mux := provRouter(ph, e.svcs)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, formPost("/admin/services/svcb/providers", url.Values{"provider_1": {"on"}}))
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.Equal(t, "/admin/services/svcb/edit?warn=reload", w.Header().Get("Location"))
	assert.Equal(t, map[int64]int64{1: 0}, e.assignments(t, "svcb"), "lagringen står")
	assert.Empty(t, e.idps.ForService("svcb"), "registeret er uendret når omlasting feiler")
	assert.Equal(t, 1, e.auditCount(t, "service_providers_updated"))

	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/services/svcb/edit?warn=reload", nil))
	assert.Contains(t, w.Body.String(), "ikke tatt i bruk")
	assert.Contains(t, w.Body.String(), "Start kauth på nytt")
}

func TestServiceProviders_AuditFailure_SavedButWarned(t *testing.T) {
	e := newProvEnv(t)
	ph := NewProvidersHandler(e.q, e.sqldb, e.idps, failingAudit{})
	mux := provRouter(ph, e.svcs)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, formPost("/admin/services/svcb/providers", url.Values{"provider_1": {"on"}}))
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/admin/services/svcb/edit?warn=audit", w.Header().Get("Location"))
	assert.Equal(t, map[int64]int64{1: 0}, e.assignments(t, "svcb"))
	assert.Len(t, e.idps.ForService("svcb"), 1, "omlasting skjer selv om audit feilet")

	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/services/svcb/edit?warn=audit", nil))
	assert.Contains(t, w.Body.String(), "ikke auditert")
}

// Feiler en innsetting midt i lagringen, skal sletting rulles tilbake slik at
// tjenesten beholder forrige tilordning (alt eller ingenting).
func TestServiceProviders_InsertFailure_RollsBack(t *testing.T) {
	e := newProvEnv(t)
	_, err := e.sqldb.Exec(`CREATE TRIGGER sip_fail BEFORE INSERT ON service_identity_providers
		WHEN NEW.provider_id = 4 BEGIN SELECT RAISE(ABORT, 'simulert'); END`)
	require.NoError(t, err)
	before := e.assignments(t, "svca")

	w := e.do(formPost("/admin/services/svca/providers", url.Values{
		"provider_1": {"on"}, "position_1": {"9"}, "provider_4": {"on"}, "position_4": {"10"},
	}))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, before, e.assignments(t, "svca"), "ingen delvis lagring")
	assert.Zero(t, e.auditCount(t, "service_providers_updated"))
}
