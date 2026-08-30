package db_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
)

// TestConcurrentWrites_NoBusyErrors dekker rotårsaken til at auditrader ble
// borte: uten busy_timeout gir SQLite SQLITE_BUSY umiddelbart til den andre
// skriveren. WAL hjelper ikke — den skiller lesere fra skrivere, ikke
// skrivere fra hverandre. audit.Log fyrer av én goroutine per hendelse, så
// to samtidige skriv ved innlogging er normaltilfellet, ikke unntaket.
func TestConcurrentWrites_NoBusyErrors(t *testing.T) {
	sqldb, q, err := db.Open(filepath.Join(t.TempDir(), "kauth.db"))
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })

	const writers = 16
	var wg sync.WaitGroup
	errs := make(chan error, writers)

	for i := range writers {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			email := "bruker@example.com"
			if err := q.InsertAuditEvent(context.Background(), gen.InsertAuditEventParams{
				EventType: "login_success", Email: &email, Success: 1,
				CreatedAt: "2026-08-30T12:00:00Z",
			}); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		assert.NoError(t, err, "samtidige skriv må ikke gi SQLITE_BUSY")
	}

	count, err := q.CountAuditEvents(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(writers), count, "alle hendelser må ha kommet fram")
}

func TestOpen_SetsBusyTimeout(t *testing.T) {
	sqldb, _, err := db.Open(filepath.Join(t.TempDir(), "kauth.db"))
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })

	var timeout int
	require.NoError(t, sqldb.QueryRow("PRAGMA busy_timeout").Scan(&timeout))
	assert.Positive(t, timeout, "uten busy_timeout gir SQLite opp ved første kollisjon")
}
