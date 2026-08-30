package db_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zral/kauth-go/internal/db/gen"
)

// hash64 lager en token_hash som tilfredsstiller CHECK (length = 64).
func hash64(seed string) string {
	return seed + strings.Repeat("0", 64-len(seed))
}

// TestDeleteExpiredRefreshTokens_ParentWithSurvivingChild dekker rotårsaken til
// at oppryddingen feilet hver time: parent_id peker på samme tabell uten
// ON DELETE, så en utløpt forelder med et levende barn blokkerte hele
// DELETE-setningen — og dermed slettingen av alle andre utløpte tokens også.
func TestDeleteExpiredRefreshTokens_ParentWithSurvivingChild(t *testing.T) {
	ctx := context.Background()
	sqldb, q := openTestDB(t)

	const now = "2026-08-30T12:00:00Z"
	insert := func(hash, expires string, parent *int64) {
		t.Helper()
		require.NoError(t, q.InsertRefreshToken(ctx, gen.InsertRefreshTokenParams{
			TokenHash: hash64(hash), Email: "lars@spekto.no", FamilyID: "fam-1",
			ParentID: parent, CreatedAt: "2026-08-01T10:00:00Z", ExpiresAt: expires,
		}))
	}

	insert("parent", "2026-08-02T10:00:00Z", nil) // utløpt
	var parentID int64
	require.NoError(t, sqldb.QueryRowContext(ctx,
		"SELECT id FROM refresh_tokens WHERE token_hash = ?", hash64("parent")).Scan(&parentID))

	insert("child", "2027-01-01T10:00:00Z", &parentID) // lever fortsatt
	insert("other", "2026-08-03T10:00:00Z", nil)       // utløpt, urelatert

	err := q.DeleteExpiredRefreshTokens(ctx, gen.DeleteExpiredRefreshTokensParams{
		ExpiresAt: now, FamilyExpiresAt: strPtr(now),
	})
	require.NoError(t, err, "utløpt forelder med levende barn må ikke blokkere oppryddingen")

	var remaining int64
	require.NoError(t, sqldb.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM refresh_tokens").Scan(&remaining))
	assert.Equal(t, int64(1), remaining, "begge utløpte tokens skal være slettet")

	var childParent *int64
	require.NoError(t, sqldb.QueryRowContext(ctx,
		"SELECT parent_id FROM refresh_tokens WHERE token_hash = ?", hash64("child")).Scan(&childParent))
	assert.Nil(t, childParent, "barnets peker til slettet forelder skal nulles")
}

func strPtr(s string) *string { return &s }
