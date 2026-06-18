package db

import (
	"database/sql"
	"embed"
	"fmt"
	"sync"

	"github.com/pressly/goose/v3"
	"github.com/zral/kauth-go/internal/db/gen"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

var setupGoose sync.Once

func Open(path string) (*sql.DB, *gen.Queries, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)", path)
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("åpne database: %w", err)
	}
	if err := sqldb.Ping(); err != nil {
		return nil, nil, fmt.Errorf("ping database: %w", err)
	}

	setupGoose.Do(func() {
		goose.SetBaseFS(migrations)
		goose.SetDialect("sqlite3") //nolint:errcheck
		goose.SetLogger(goose.NopLogger())
	})
	if err := goose.Up(sqldb, "migrations"); err != nil {
		return nil, nil, fmt.Errorf("migrasjoner: %w", err)
	}

	return sqldb, gen.New(sqldb), nil
}

// OpenMemory brukes i tester
func OpenMemory() (*sql.DB, *gen.Queries, error) {
	return Open(":memory:")
}
