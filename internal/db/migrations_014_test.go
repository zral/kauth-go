package db

import (
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

func TestMigration014_UpDownKeepsOldColumns(t *testing.T) {
	d := openRaw(t)
	require.NoError(t, goose.UpTo(d, "migrations", 13))
	addService(t, d, "s1", 1)
	_, err := d.Exec(`UPDATE services SET google_client_secret='g-klar', microsoft_client_secret='m-klar' WHERE id='s1'`)
	require.NoError(t, err)

	require.NoError(t, goose.UpTo(d, "migrations", 14))
	var g, m string
	require.NoError(t, d.QueryRow(`SELECT google_client_secret, microsoft_client_secret FROM services WHERE id='s1'`).Scan(&g, &m))
	require.Equal(t, "g-klar", g)
	require.Equal(t, "m-klar", m)
	require.Equal(t, 1, count(t, d, `SELECT count(*) FROM services WHERE google_client_secret_env IS NULL AND microsoft_client_secret_env IS NULL`))

	require.NoError(t, goose.DownTo(d, "migrations", 13))
	require.Equal(t, int64(13), gooseVersion(t, d))
	require.NoError(t, d.QueryRow(`SELECT google_client_secret, microsoft_client_secret FROM services WHERE id='s1'`).Scan(&g, &m))
	require.Equal(t, "g-klar", g)
	require.Equal(t, "m-klar", m)
	require.Equal(t, 0, count(t, d, `SELECT count(*) FROM pragma_table_info('services') WHERE name LIKE '%_secret_env'`))
}

func TestMigration014_Check(t *testing.T) {
	d, _ := openMigrated(t)
	addService(t, d, "s1", 1)
	for _, col := range []string{"google_client_secret_env", "microsoft_client_secret_env"} {
		for val, ok := range map[string]bool{
			"KAUTH_SVC_A_SECRET":    true,
			"KAUTH_SVC_X1":          true,
			"KAUTH_IDP_ACME":        false,
			"KAUTH_PRIVATE_KEY_PEM": false,
			"PATH":                  false,
			"kauth_svc_a":           false,
			"KAUTH_SVC_a_secret":    false,
			"KAUTH_SVC_A-B":         false,
			"KAUTH_SVC_A B":         false,
			"KAUTH_SVC_":            false,
			"KAUTH_SVC_Å":           false,
			"":                      false,
		} {
			_, err := d.Exec(`UPDATE services SET `+col+`=? WHERE id='s1'`, val)
			if ok {
				require.NoError(t, err, "%s=%s", col, val)
			} else {
				require.Error(t, err, "%s=%s", col, val)
			}
		}
		_, err := d.Exec(`UPDATE services SET ` + col + `=NULL WHERE id='s1'`)
		require.NoError(t, err)
	}
}
