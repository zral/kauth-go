package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 011 F4 (PD15): sub_format og auto_link følger samme lagringskontrakt som resten av skjemaet.

func (e *svcEnv) setPolicy(t *testing.T, id, subFormat string, autoLink int) {
	t.Helper()
	_, err := e.sqldb.Exec(`UPDATE services SET sub_format = ?, auto_link = ? WHERE id = ?`, subFormat, autoLink, id)
	require.NoError(t, err)
}

func (e *svcEnv) editDetails(t *testing.T, id string) string {
	t.Helper()
	var d string
	require.Eventually(t, func() bool {
		return e.sqldb.QueryRow(
			`SELECT COALESCE(details,'') FROM audit_events WHERE event_type = 'service_edited' AND service_id = ? ORDER BY id DESC LIMIT 1`, id,
		).Scan(&d) == nil
	}, 2*time.Second, 10*time.Millisecond)
	return d
}

func TestServiceUpdate_PreservesSubFormatAndAutoLink(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	e.setPolicy(t, "alpha", "id", 0)

	// Skjema uten feltene (eldre side/skript): verdiene beholdes.
	vals, _ := e.renderedFormValues(t, "alpha")
	vals.Del("sub_format")
	vals.Del("auto_link")
	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)
	row := e.row(t, "alpha")
	assert.Equal(t, "id", row.SubFormat)
	assert.EqualValues(t, 0, row.AutoLink)

	// Rendret skjema uendret tur-retur: også beholdt (avkrysning av gir skjult 0).
	vals, body := e.renderedFormValues(t, "alpha")
	assert.Equal(t, "id", vals.Get("sub_format"))
	assert.Equal(t, []string{"0"}, vals["auto_link"])
	assert.Contains(t, body, `type="hidden" name="auto_link" value="0"`)
	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)
	row = e.row(t, "alpha")
	assert.Equal(t, "id", row.SubFormat)
	assert.EqualValues(t, 0, row.AutoLink)

	// Med feltene endret: lagres og auditeres med gammel og ny verdi.
	vals.Set("sub_format", "email")
	vals.Set("auto_link", "1")
	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)
	row = e.row(t, "alpha")
	assert.Equal(t, "email", row.SubFormat)
	assert.EqualValues(t, 1, row.AutoLink)
	d := e.editDetails(t, "alpha")
	assert.Contains(t, d, "sub_format=id->email")
	assert.Contains(t, d, "auto_link=0->1")

	// Avkrysning fjernet i nettleseren: bare det skjulte 0 sendes.
	vals.Set("auto_link", "0")
	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)
	assert.EqualValues(t, 0, e.row(t, "alpha").AutoLink)
}

func TestServiceUpdate_RejectsInvalidSubFormat(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	before := e.row(t, "alpha")

	vals, _ := e.renderedFormValues(t, "alpha")
	vals.Set("display_name", "Skal ikke lagres")
	vals.Set("sub_format", "foo")
	w := e.post("alpha", vals)
	require.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "Ugyldig sub-format")
	assert.Equal(t, before, e.row(t, "alpha"))

	// Opprettelse validerer likt.
	vals.Set("id", "gamma")
	assert.Equal(t, http.StatusUnprocessableEntity, e.postCreate(vals).Code)
}

func TestServiceCreate_Defaults(t *testing.T) {
	e := setupServicesEnv(t)

	// Uten feltene i POST: DB-defaultene gjelder.
	w := e.postCreate(url.Values{
		"id": {"gamma"}, "display_name": {"Gamma"}, "domain": {"gamma.test"},
		"callback_url": {"https://gamma.test/cb"}, "active": {"1"},
	})
	require.Equal(t, http.StatusSeeOther, w.Code)
	row := e.row(t, "gamma")
	assert.Equal(t, "email", row.SubFormat)
	assert.EqualValues(t, 1, row.AutoLink)

	// Nytt-skjemaet forhåndsvelger samme standard.
	vals, _ := e.renderedFormValues(t, "gamma")
	assert.Equal(t, "email", vals.Get("sub_format"))
	assert.Equal(t, []string{"0", "1"}, vals["auto_link"], "skjult 0 foran krysset 1, som i nettleseren")

	// Med verdier fra skjemaet.
	w = e.postCreate(url.Values{
		"id": {"delta"}, "display_name": {"Delta"}, "domain": {"delta.test"},
		"callback_url": {"https://delta.test/cb"}, "active": {"1"},
		"sub_format": {"id"}, "auto_link": {"0", ""},
	})
	require.Equal(t, http.StatusSeeOther, w.Code)
	row = e.row(t, "delta")
	assert.Equal(t, "id", row.SubFormat)
	assert.EqualValues(t, 0, row.AutoLink)
	d := e.createDetails(t, "delta")
	assert.Contains(t, d, "sub_format=id auto_link=0")
	assert.Contains(t, e.createDetails(t, "gamma"), "sub_format=email auto_link=1")
}

func (e *svcEnv) createDetails(t *testing.T, id string) string {
	t.Helper()
	var d string
	require.Eventually(t, func() bool {
		return e.sqldb.QueryRow(
			`SELECT COALESCE(details,'') FROM audit_events WHERE event_type = 'service_created' AND service_id = ?`, id,
		).Scan(&d) == nil
	}, 2*time.Second, 10*time.Millisecond)
	return d
}

// Nettleserens form-kodinger: [0] = av, [0,1] = på, mangler = uendret.
func TestServiceUpdate_AutoLinkMultiValue(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	e.setPolicy(t, "alpha", "email", 1)
	vals, _ := e.renderedFormValues(t, "alpha")
	vals.Del("auto_link")

	vals["auto_link"] = []string{"0"}
	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)
	assert.EqualValues(t, 0, e.row(t, "alpha").AutoLink)

	vals["auto_link"] = []string{"0", "1"}
	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)
	assert.EqualValues(t, 1, e.row(t, "alpha").AutoLink)

	e.setPolicy(t, "alpha", "email", 0)
	vals.Del("auto_link")
	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)
	assert.EqualValues(t, 0, e.row(t, "alpha").AutoLink)
}

func TestServiceUpdate_InvalidSubFormatErrorPageShowsStored(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	e.setPolicy(t, "alpha", "id", 1)
	for _, bad := range []string{"foo", ""} {
		vals, _ := e.renderedFormValues(t, "alpha")
		vals.Set("sub_format", bad)
		w := e.post("alpha", vals)
		require.Equal(t, http.StatusUnprocessableEntity, w.Code, bad)
		assert.Contains(t, w.Body.String(), "Ugyldig sub-format")
		got := parseFormValues(t, w.Body.String())
		assert.Equal(t, "id", got.Get("sub_format"), bad)
		assert.Equal(t, "id", e.row(t, "alpha").SubFormat)
	}
}

func TestServiceNew_ShowsDefaults(t *testing.T) {
	e := setupServicesEnv(t)
	h := NewServicesHandler(e.q, e.reg, nil)
	w := httptest.NewRecorder()
	h.HandleNew(w, httptest.NewRequest(http.MethodGet, "/admin/services/new", nil))
	require.Equal(t, http.StatusOK, w.Code)
	vals := parseFormValues(t, w.Body.String())
	assert.Equal(t, "email", vals.Get("sub_format"))
	assert.Equal(t, []string{"0", "1"}, vals["auto_link"])
}
