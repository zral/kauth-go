package admin

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const envKnownSecret = "hemmelig-verdi-ABC123-xyz"

func TestServiceSecretEnv_SaveShowAndStatus(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	t.Setenv("KAUTH_SVC_ALFA_G", envKnownSecret)
	t.Setenv("KAUTH_SVC_ALFA_M", "")

	vals, _ := e.renderedFormValues(t, "alpha")
	vals.Set("google_secret_env", "KAUTH_SVC_ALFA_G")
	vals.Set("microsoft_secret_env", "KAUTH_SVC_ALFA_M")
	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)

	row := e.row(t, "alpha")
	require.NotNil(t, row.GoogleClientSecretEnv)
	assert.Equal(t, "KAUTH_SVC_ALFA_G", *row.GoogleClientSecretEnv)
	assert.Equal(t, "KAUTH_SVC_ALFA_M", *row.MicrosoftClientSecretEnv)

	got, body := e.renderedFormValues(t, "alpha")
	assert.Equal(t, "KAUTH_SVC_ALFA_G", got.Get("google_secret_env"))
	assert.Contains(t, body, `<span class="badge badge-green">satt</span>`)
	assert.Contains(t, body, `<span class="badge badge-red">ikke satt</span>`)
	assert.Contains(t, body, `aria-describedby="secret_env_hint google_secret_status"`)
	assert.Contains(t, body, "Microsoft-innlogging er ute av drift for denne tjenesten til KAUTH_SVC_ALFA_M er satt i .env")
	assert.NotContains(t, body, "Google-innlogging er ute av drift")
	// Klartekst ligger igjen fra seed: merknad uten verdi.
	assert.Contains(t, body, "Hemmelighet ligger i databasen; flytt den til en miljøvariabel.")
	for _, v := range []string{envKnownSecret, "g-secret-alpha", "m-secret-alpha"} {
		assert.NotContains(t, body, v)
	}
	// Gamle kolonner bevart.
	require.NotNil(t, row.GoogleClientSecret)
	assert.Equal(t, "g-secret-alpha", *row.GoogleClientSecret)
	assert.Equal(t, "m-secret-alpha", *row.MicrosoftClientSecret)
}

func TestServiceSecretEnv_NoPlaintextNoNote(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	_, err := e.sqldb.Exec(`UPDATE services SET google_client_secret = NULL, microsoft_client_secret = '' WHERE id = 'alpha'`)
	require.NoError(t, err)
	_, body := e.renderedFormValues(t, "alpha")
	assert.NotContains(t, body, "Hemmelighet ligger i databasen")
	assert.Contains(t, body, "Ingen referanse")
	assert.NotContains(t, body, "ute av drift")
}

func TestServiceSecretEnv_InvalidRejected(t *testing.T) {
	e := setupServicesEnv(t)
	for _, bad := range []string{"GOOGLE_SECRET", "kauth_svc_x", "KAUTH_SVC_lower", "KAUTH_PRIVATE_KEY_PEM", "KAUTH_SVC_", "KAUTH_SVC_A B", "KAUTH_SVC_" + strings.Repeat("A", 55)} {
		_, _ = e.sqldb.Exec(`DELETE FROM services`)
		e.seed(t, "alpha", "alpha.test")
		before := e.row(t, "alpha")

		vals, _ := e.renderedFormValues(t, "alpha")
		vals.Set("display_name", "Endret")
		vals.Set("microsoft_secret_env", bad)
		w := e.post("alpha", vals)
		require.Equal(t, http.StatusUnprocessableEntity, w.Code, bad)
		assert.Contains(t, w.Body.String(), "Microsoft: miljøvariabelen må hete KAUTH_SVC_", bad)
		assert.Equal(t, before, e.row(t, "alpha"), bad)

		// Skjemaet beholdes (fornavnet og det ugyldige navnet), ellers uendret.
		got := parseFormValues(t, w.Body.String())
		assert.Equal(t, "Endret", got.Get("display_name"), bad)
		assert.Equal(t, bad, got.Get("microsoft_secret_env"), bad)

		// Opprettelse avvises likt.
		cv := url.Values{"id": {"ny"}, "display_name": {"N"}, "domain": {"n.test"}, "callback_url": {"https://n.test/cb"}, "google_secret_env": {bad}}
		cw := e.postCreate(cv)
		require.Equal(t, http.StatusUnprocessableEntity, cw.Code, bad)
		var n int
		require.NoError(t, e.sqldb.QueryRow(`SELECT COUNT(*) FROM services WHERE id = 'ny'`).Scan(&n))
		assert.Zero(t, n, bad)
	}
}

func TestServiceSecretEnv_EmptyGivesNullAndAudit(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")

	vals, _ := e.renderedFormValues(t, "alpha")
	vals.Set("google_secret_env", "KAUTH_SVC_ALFA_G")
	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)
	assert.Contains(t, e.editDetails(t, "alpha"), "google_secret_env=(ingen)->KAUTH_SVC_ALFA_G")

	_, err := e.sqldb.Exec(`DELETE FROM audit_events`)
	require.NoError(t, err)
	vals, _ = e.renderedFormValues(t, "alpha")
	vals.Set("google_secret_env", "  ")
	vals.Set("microsoft_secret_env", "KAUTH_SVC_ALFA_M")
	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)

	row := e.row(t, "alpha")
	assert.Nil(t, row.GoogleClientSecretEnv)
	require.NotNil(t, row.MicrosoftClientSecretEnv)
	d := e.editDetails(t, "alpha")
	assert.Contains(t, d, "google_secret_env=KAUTH_SVC_ALFA_G->(ingen)")
	assert.Contains(t, d, "microsoft_secret_env=(ingen)->KAUTH_SVC_ALFA_M")

	// Uendret navn gir ingen audit-linje om det.
	_, err = e.sqldb.Exec(`DELETE FROM audit_events`)
	require.NoError(t, err)
	vals, _ = e.renderedFormValues(t, "alpha")
	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)
	assert.NotContains(t, e.editDetails(t, "alpha"), "secret_env")
}

func TestServiceSecretEnv_AbsentFieldKeepsStored(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	_, err := e.sqldb.Exec(`UPDATE services SET google_client_secret_env = 'KAUTH_SVC_ALFA_G' WHERE id = 'alpha'`)
	require.NoError(t, err)

	vals, _ := e.renderedFormValues(t, "alpha")
	vals.Del("google_secret_env")
	vals.Del("microsoft_secret_env")
	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)
	assert.Equal(t, "KAUTH_SVC_ALFA_G", *e.row(t, "alpha").GoogleClientSecretEnv)
}

func TestServiceSecretEnv_CreateStoresAndAudits(t *testing.T) {
	e := setupServicesEnv(t)
	t.Setenv("KAUTH_SVC_NY_G", envKnownSecret)
	cv := url.Values{"id": {"ny"}, "display_name": {"N"}, "domain": {"n.test"}, "callback_url": {"https://n.test/cb"}, "google_secret_env": {"KAUTH_SVC_NY_G"}}
	require.Equal(t, http.StatusSeeOther, e.postCreate(cv).Code)
	row := e.row(t, "ny")
	require.NotNil(t, row.GoogleClientSecretEnv)
	assert.Equal(t, "KAUTH_SVC_NY_G", *row.GoogleClientSecretEnv)
	assert.Nil(t, row.MicrosoftClientSecretEnv)

	var d string
	require.Eventually(t, func() bool {
		return e.sqldb.QueryRow(`SELECT COALESCE(details,'') FROM audit_events WHERE event_type = 'service_created' AND service_id = 'ny'`).Scan(&d) == nil
	}, 2e9, 1e7)
	assert.Contains(t, d, "google_secret_env=(ingen)->KAUTH_SVC_NY_G")
	assert.NotContains(t, d, envKnownSecret)
}
