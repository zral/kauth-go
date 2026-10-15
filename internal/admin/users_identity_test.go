package admin

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnlink_DeletesAndRevokes(t *testing.T) {
	e := newF3Env(t)
	u := e.mkUser(t, "ola@example.com")
	other := e.mkUser(t, "kari@example.com")
	gid := e.addIdentity(t, u.ID, "google", "112233445566778899001")
	keep := e.addIdentity(t, u.ID, "microsoft", msOid)
	_, err := e.sqldb.Exec("UPDATE user_identities SET admin_ok = 1 WHERE id = ?", gid)
	require.NoError(t, err)
	e.addIdentity(t, other.ID, "google", "999888777666555444333")

	t1, t2 := e.issueFamily(t, u), e.issueFamily(t, u)
	tOther := e.issueFamily(t, other)

	w := e.post(unlinkPath(u.ID, gid), nil)
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.Equal(t, "/admin/users/"+id64(u.ID)+"/edit", w.Header().Get("Location"))

	var n int
	require.NoError(t, e.sqldb.QueryRow("SELECT COUNT(*) FROM user_identities WHERE id = ?", gid).Scan(&n))
	assert.Zero(t, n, "identiteten er borte")
	require.NoError(t, e.sqldb.QueryRow("SELECT COUNT(*) FROM user_identities WHERE id = ?", keep).Scan(&n))
	assert.Equal(t, 1, n, "brukerens andre identitet står")

	for _, tok := range []string{t1, t2} {
		rv, reason := e.rtState(t, tok)
		assert.EqualValues(t, 1, rv)
		assert.Equal(t, "identity_unlinked", reason.String)
	}
	rv, _ := e.rtState(t, tOther)
	assert.EqualValues(t, 0, rv, "annen brukers familie står")

	email, d := e.auditRow(t, "identity_unlinked")
	assert.Equal(t, "ola@example.com", email)
	for _, want := range []string{
		"id=" + id64(u.ID), "identity=" + id64(gid), "provider=google",
		"issuer=https://accounts.google.com", "admin_ok=1", "revoked=2", "actor=" + testActor,
	} {
		assert.Contains(t, d, want)
	}
	assert.NotContains(t, d, "112233445566778899001", "subject logges ikke")
}

func TestUnlink_OtherUsersIdentity_404(t *testing.T) {
	e := newF3Env(t)
	u := e.mkUser(t, "ola@example.com")
	other := e.mkUser(t, "kari@example.com")
	foreign := e.addIdentity(t, other.ID, "google", "999888777666555444333")
	tok := e.issueFamily(t, u)
	tokOther := e.issueFamily(t, other)

	w := e.post(unlinkPath(u.ID, foreign), nil)
	assert.Equal(t, http.StatusNotFound, w.Code)

	var n int
	require.NoError(t, e.sqldb.QueryRow("SELECT COUNT(*) FROM user_identities WHERE id = ?", foreign).Scan(&n))
	assert.Equal(t, 1, n, "raden står")
	for _, tk := range []string{tok, tokOther} {
		rv, _ := e.rtState(t, tk)
		assert.EqualValues(t, 0, rv, "ingenting revokert")
	}
	assert.Zero(t, e.auditCount(t, "identity_unlinked"))

	// Ukjente og ikke-numeriske ID-er gir også 404.
	assert.Equal(t, http.StatusNotFound, e.post(unlinkPath(u.ID, 99999), nil).Code)
	assert.Equal(t, http.StatusNotFound, e.post("/admin/users/abc/identities/1/unlink", nil).Code)
	assert.Equal(t, http.StatusNotFound, e.post("/admin/users/"+id64(u.ID)+"/identities/abc/unlink", nil).Code)
}

func TestUnlink_RevokeFails_RollsBack(t *testing.T) {
	e := newF3Env(t)
	u := e.mkUser(t, "ola@example.com")
	gid := e.addIdentity(t, u.ID, "google", "112233445566778899001")
	tok := e.issueFamily(t, u)
	_, err := e.sqldb.Exec(`CREATE TRIGGER fail_revoke BEFORE UPDATE ON refresh_tokens BEGIN SELECT RAISE(ABORT,'x'); END`)
	require.NoError(t, err)

	w := e.post(unlinkPath(u.ID, gid), nil)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "databasefeil\n", w.Body.String())

	var n int
	require.NoError(t, e.sqldb.QueryRow("SELECT COUNT(*) FROM user_identities WHERE id = ?", gid).Scan(&n))
	assert.Equal(t, 1, n, "slettingen er rullet tilbake")
	rv, _ := e.rtState(t, tok)
	assert.EqualValues(t, 0, rv)
	assert.Zero(t, e.auditCount(t, "identity_unlinked"))
}

func TestUnlink_DeactivatedUser_Allowed(t *testing.T) {
	e := newF3Env(t)
	u := e.mkUser(t, "ola@example.com")
	gid := e.addIdentity(t, u.ID, "google", "112233445566778899001")
	w := e.deactivate(id64(u.ID))
	require.Equal(t, http.StatusSeeOther, w.Code)

	w = e.post(unlinkPath(u.ID, gid), nil)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	var n int
	require.NoError(t, e.sqldb.QueryRow("SELECT COUNT(*) FROM user_identities WHERE id = ?", gid).Scan(&n))
	assert.Zero(t, n)
}

func TestUnlink_KeepsAdminBound(t *testing.T) {
	e := newF3Env(t)
	u := e.mkUser(t, "konge@example.com")
	gid := e.addIdentity(t, u.ID, "google", "112233445566778899001")
	const bound = "2026-10-05T12:00:00Z"
	_, err := e.sqldb.Exec("UPDATE users SET admin_bound_at = ? WHERE id = ?", bound, u.ID)
	require.NoError(t, err)
	_, err = e.sqldb.Exec("UPDATE user_identities SET admin_ok = 1 WHERE id = ?", gid)
	require.NoError(t, err)

	require.Equal(t, http.StatusSeeOther, e.post(unlinkPath(u.ID, gid), nil).Code)

	var got *string
	require.NoError(t, e.sqldb.QueryRow("SELECT admin_bound_at FROM users WHERE id = ?", u.ID).Scan(&got))
	require.NotNil(t, got)
	assert.Equal(t, bound, *got)

	// Siden forklarer at bindingen står uten noen godkjent identitet.
	body := e.get("/admin/users/" + id64(u.ID) + "/edit").Body.String()
	assert.Contains(t, body, "Admin-Google er bundet")
	assert.Contains(t, body, "driftsprosedyren")
}
