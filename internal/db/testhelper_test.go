package db_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
)

// openTestDB opens an in-memory SQLite database, runs migrations, and returns
// the raw *sql.DB and a *gen.Queries ready for use in tests.
func openTestDB(t *testing.T) (*sql.DB, *gen.Queries) {
	t.Helper()
	sqldb, q, err := db.OpenMemory()
	if err != nil {
		t.Fatalf("openTestDB: %v", err)
	}
	t.Cleanup(func() { sqldb.Close() })
	return sqldb, q
}

func TestOpenMemory(t *testing.T) {
	_, q := openTestDB(t)
	ctx := context.Background()

	_, err := q.CountUsers(ctx)
	require.NoError(t, err, "CountUsers: alle migrasjoner må ha kjørt")

	_, err = q.CountAuditEvents(ctx)
	require.NoError(t, err, "CountAuditEvents: alle migrasjoner må ha kjørt")

	_, err = q.CountRefreshTokens(ctx)
	require.NoError(t, err, "CountRefreshTokens: alle migrasjoner må ha kjørt")
}
