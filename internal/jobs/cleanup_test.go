package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/token"
)

func TestCleanLinkInvites_DeletesOnlyOlderThanSevenDays(t *testing.T) {
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })
	for _, s := range []string{
		`INSERT INTO users (id,email,roles,orgs,created_at,public_id) VALUES (1,'a@b.no','user','','2026-10-01T10:00:00Z','p1')`,
		`INSERT INTO identity_providers (id,slug,display_name,issuer,client_id) VALUES (1,'acme','Acme','https://i.example','c')`,
		`INSERT INTO services (id,display_name,domain,callback_url,theme,accent_color,email_from_name,jwt_cookie_name,access_token_ttl,active,updated_at)
		 VALUES ('s','s','s.test','https://s.test/cb','light','#000','s','s_tok','PT30M',1,'2026-10-01T10:00:00Z')`,
	} {
		_, err := sqldb.Exec(s)
		require.NoError(t, err, s)
	}
	now := time.Now()
	ins := func(hash string, expires time.Time, used bool) {
		var usedAt any
		if used {
			usedAt = token.FormatLinkInviteTime(now)
		}
		_, err := sqldb.Exec(`INSERT INTO identity_link_invites (token_hash,user_id,provider_id,service_id,email,created_by,created_at,expires_at,used_at)
			VALUES (?,1,1,'s','a@b.no','x',?,?,?)`, hash, token.FormatLinkInviteTime(expires.Add(-24*time.Hour)), token.FormatLinkInviteTime(expires), usedAt)
		require.NoError(t, err)
	}
	ins("gammel-utlopt", now.Add(-8*24*time.Hour), false)
	ins("gammel-brukt", now.Add(-8*24*time.Hour), true)
	ins("nylig-utlopt", now.Add(-1*time.Hour), false)
	ins("aktiv", now.Add(10*time.Hour), false)

	NewCleanup(q).cleanLinkInvites(context.Background())

	rows, err := sqldb.Query(`SELECT token_hash FROM identity_link_invites ORDER BY id`)
	require.NoError(t, err)
	defer rows.Close()
	var left []string
	for rows.Next() {
		var h string
		require.NoError(t, rows.Scan(&h))
		left = append(left, h)
	}
	require.Equal(t, []string{"nylig-utlopt", "aktiv"}, left)
}
