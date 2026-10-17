package admin

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/db/gen"
)

func TestServiceGitHub_EditSavesShowsAndAudits(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	t.Setenv("KAUTH_SVC_ALFA_GH", envKnownSecret)
	t.Setenv("KAUTH_SVC_ALFA_GH2", "")

	vals, _ := e.renderedFormValues(t, "alpha")
	vals.Set("auth_github", "1")
	vals.Set("github_client_id", "  Iv1.abc123  ")
	vals.Set("github_secret_env", "KAUTH_SVC_ALFA_GH")
	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)

	row := e.row(t, "alpha")
	assert.EqualValues(t, 1, row.AuthGithub)
	require.NotNil(t, row.GithubClientID)
	assert.Equal(t, "Iv1.abc123", *row.GithubClientID)
	require.NotNil(t, row.GithubClientSecretEnv)
	assert.Equal(t, "KAUTH_SVC_ALFA_GH", *row.GithubClientSecretEnv)

	got, body := e.renderedFormValues(t, "alpha")
	assert.Equal(t, "1", got.Get("auth_github"))
	assert.Equal(t, "Iv1.abc123", got.Get("github_client_id"))
	assert.Equal(t, "KAUTH_SVC_ALFA_GH", got.Get("github_secret_env"))
	assert.Contains(t, body, `aria-describedby="secret_env_hint github_secret_status"`)
	assert.Contains(t, body, `<span class="badge badge-green">satt</span>`)
	assert.NotContains(t, body, envKnownSecret)

	d := e.editDetails(t, "alpha")
	assert.Contains(t, d, "auth_github=0->1")
	assert.Contains(t, d, "github_secret_env=(ingen)->KAUTH_SVC_ALFA_GH")
	assert.NotContains(t, d, envKnownSecret)

	// Peker mot en variabel som ikke er satt: «ikke satt» og advarsel.
	vals.Set("github_secret_env", "KAUTH_SVC_ALFA_GH2")
	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)
	_, body = e.renderedFormValues(t, "alpha")
	assert.Contains(t, body, `<span class="badge badge-red">ikke satt</span>`)
	assert.Contains(t, body, "GitHub-innlogging er ute av drift for denne tjenesten til KAUTH_SVC_ALFA_GH2 er satt i .env")
}

func TestServiceGitHub_InvalidPrefixRejected(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	before := e.row(t, "alpha")

	vals, _ := e.renderedFormValues(t, "alpha")
	vals.Set("github_secret_env", "KAUTH_PRIVATE_KEY_PEM")
	w := e.post("alpha", vals)
	require.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "GitHub: miljøvariabelen må hete KAUTH_SVC_")
	assert.Equal(t, before, e.row(t, "alpha"))
	assert.Equal(t, "KAUTH_PRIVATE_KEY_PEM", parseFormValues(t, w.Body.String()).Get("github_secret_env"))

	cv := url.Values{"id": {"ny"}, "display_name": {"N"}, "domain": {"n.test"}, "callback_url": {"https://n.test/cb"}, "github_secret_env": {"nope"}}
	w = e.postCreate(cv)
	require.Equal(t, http.StatusUnprocessableEntity, w.Code)
	var n int
	require.NoError(t, e.sqldb.QueryRow(`SELECT COUNT(*) FROM services WHERE id = 'ny'`).Scan(&n))
	assert.Zero(t, n)
}

func TestServiceGitHub_ErrorRerenderKeepsFields(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	vals, _ := e.renderedFormValues(t, "alpha")
	vals.Set("auth_github", "1")
	vals.Set("github_client_id", "Iv1.typed")
	vals.Set("github_secret_env", "bad")
	w := e.post("alpha", vals)
	require.Equal(t, http.StatusUnprocessableEntity, w.Code)
	got := parseFormValues(t, w.Body.String())
	assert.Equal(t, "1", got.Get("auth_github"))
	assert.Equal(t, "Iv1.typed", got.Get("github_client_id"))
}

func TestServiceGitHub_CreateStoresAndAudits(t *testing.T) {
	e := setupServicesEnv(t)
	cv := url.Values{"id": {"ny"}, "display_name": {"N"}, "domain": {"n.test"}, "callback_url": {"https://n.test/cb"},
		"auth_github": {"1"}, "github_client_id": {"Iv1.ny"}, "github_secret_env": {"KAUTH_SVC_NY_GH"}}
	require.Equal(t, http.StatusSeeOther, e.postCreate(cv).Code)
	row := e.row(t, "ny")
	assert.EqualValues(t, 1, row.AuthGithub)
	require.NotNil(t, row.GithubClientID)
	assert.Equal(t, "Iv1.ny", *row.GithubClientID)
	require.NotNil(t, row.GithubClientSecretEnv)
	assert.Equal(t, "KAUTH_SVC_NY_GH", *row.GithubClientSecretEnv)

	var d string
	require.Eventually(t, func() bool {
		return e.sqldb.QueryRow(`SELECT COALESCE(details,'') FROM audit_events WHERE event_type = 'service_created' AND service_id = 'ny'`).Scan(&d) == nil
	}, 2e9, 1e7)
	assert.Contains(t, d, "auth_github=1")
	assert.Contains(t, d, "github_secret_env=(ingen)->KAUTH_SVC_NY_GH")
}

func TestServiceGitHub_AbsentFieldsKeepStored(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	_, err := e.sqldb.Exec(`UPDATE services SET auth_github = 1, github_client_id = 'Iv1.keep', github_client_secret_env = 'KAUTH_SVC_ALFA_GH' WHERE id = 'alpha'`)
	require.NoError(t, err)

	vals, _ := e.renderedFormValues(t, "alpha")
	vals.Del("github_client_id")
	vals.Del("github_secret_env")
	vals.Set("display_name", "Endret")
	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)

	row := e.row(t, "alpha")
	assert.Equal(t, "Endret", row.DisplayName)
	assert.EqualValues(t, 1, row.AuthGithub)
	require.NotNil(t, row.GithubClientID)
	assert.Equal(t, "Iv1.keep", *row.GithubClientID)
	require.NotNil(t, row.GithubClientSecretEnv)
	assert.Equal(t, "KAUTH_SVC_ALFA_GH", *row.GithubClientSecretEnv)
	assert.NotContains(t, e.editDetails(t, "alpha"), "github")

	// Tomme felt i skjemaet er derimot et eksplisitt ønske om å fjerne verdien.
	vals.Set("github_client_id", "")
	vals.Set("github_secret_env", "")
	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)
	row = e.row(t, "alpha")
	assert.Nil(t, row.GithubClientID)
	assert.Nil(t, row.GithubClientSecretEnv)
}

// Client id er offentlig og redigerbar; den skal ikke skjules som Google/MS-id.
func TestWithoutSecrets_KeepsGithubClientID(t *testing.T) {
	id := "Iv1.abc"
	out := withoutSecrets(gen.Service{GithubClientID: &id})
	require.NotNil(t, out.GithubClientID)
	assert.Equal(t, "Iv1.abc", *out.GithubClientID)
}

// Tømt client id skal vises tom på feilsiden, ikke som den lagrede verdien.
func TestServiceGitHub_ErrorRerenderShowsClearedClientID(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	_, err := e.sqldb.Exec(`UPDATE services SET github_client_id = 'Iv1.old' WHERE id = 'alpha'`)
	require.NoError(t, err)
	vals, _ := e.renderedFormValues(t, "alpha")
	require.Equal(t, "Iv1.old", vals.Get("github_client_id"))
	vals.Set("github_client_id", "")
	vals.Set("github_secret_env", "bad")
	w := e.post("alpha", vals)
	require.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Equal(t, "", parseFormValues(t, w.Body.String()).Get("github_client_id"))
}

func TestServiceGitHub_InvalidClientIDRejected(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	for _, bad := range []string{"Iv1 abc", "Iv1.abc&scope=repo", strings.Repeat("a", 129)} {
		vals, _ := e.renderedFormValues(t, "alpha")
		vals.Set("github_client_id", bad)
		require.Equal(t, http.StatusUnprocessableEntity, e.post("alpha", vals).Code, bad)
	}
	assert.Nil(t, e.row(t, "alpha").GithubClientID)
	cv := url.Values{"id": {"ny"}, "display_name": {"N"}, "domain": {"n.test"}, "callback_url": {"https://n.test/cb"}, "github_client_id": {"a b"}}
	require.Equal(t, http.StatusUnprocessableEntity, e.postCreate(cv).Code)
}

func TestServiceGitHub_ClientIDChangeAudited(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	_, err := e.sqldb.Exec(`UPDATE services SET github_client_id = 'Iv1.old' WHERE id = 'alpha'`)
	require.NoError(t, err)
	vals, _ := e.renderedFormValues(t, "alpha")
	vals.Set("github_client_id", "Iv1.new")
	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)
	var d string
	require.Eventually(t, func() bool {
		return e.sqldb.QueryRow(`SELECT COALESCE(details,'') FROM audit_events WHERE event_type = 'service_edited' AND service_id = 'alpha'`).Scan(&d) == nil
	}, 2e9, 1e7)
	assert.Contains(t, d, "github_client_id=Iv1.old->Iv1.new")
}

func TestIdentityViews_GitHubProvider(t *testing.T) {
	mail := "ola@example.com"
	in := []gen.UserIdentity{{ID: 1, Provider: "github", Issuer: "https://github.com", Subject: "12345678", Email: &mail}}
	got := identityViews(in, nil)
	require.Len(t, got, 1)
	assert.Equal(t, "GitHub", got[0].Provider)
	assert.False(t, got[0].Unknown)
	assert.Equal(t, "123456…", got[0].Subject)
}

func TestServiceGitHub_UncheckedBoxDisablesAndAudits(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	_, err := e.sqldb.Exec(`UPDATE services SET auth_github = 1 WHERE id = 'alpha'`)
	require.NoError(t, err)

	vals, _ := e.renderedFormValues(t, "alpha")
	vals.Del("auth_github")
	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)
	assert.EqualValues(t, 0, e.row(t, "alpha").AuthGithub)
	assert.Contains(t, e.editDetails(t, "alpha"), "auth_github=1->0")
}
