package db_test

import (
	"context"
	"database/sql"
	"testing"

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
	count, err := q.CountUsers(context.Background())
	if err != nil {
		t.Fatalf("CountUsers: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 users, got %d", count)
	}
}
