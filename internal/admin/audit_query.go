package admin

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/zral/kauth-go/internal/db/gen"
)

// auditColumns holder kolonnerekkefølgen fast mellom SELECT og Scan.
const auditColumns = "id, event_type, auth_method, email, service_id, " +
	"ip_address, user_agent, success, details, created_at"

// auditChoices er verdiene som fyller avkryssingsboksene i filterskjemaet.
// De hentes fra dataene, så nye hendelsestyper dukker opp uten kodeendring.
type auditChoices struct {
	Events   []string
	Methods  []string
	Services []string
}

// queryAuditEvents henter auditrader for et filter. Spørringen bygges dynamisk
// fordi sqlc ikke kan uttrykke IN-lister med variabel lengde.
func queryAuditEvents(ctx context.Context, sqldb *sql.DB, f auditFilter, limit, offset int64) ([]gen.AuditEvent, error) {
	where, args := buildAuditQuery(f)
	q := "SELECT " + auditColumns + " FROM audit_events" + where +
		" ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := sqldb.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("hente auditlogg: %w", err)
	}
	defer rows.Close()

	var events []gen.AuditEvent
	for rows.Next() {
		var e gen.AuditEvent
		if err := rows.Scan(&e.ID, &e.EventType, &e.AuthMethod, &e.Email, &e.ServiceID,
			&e.IpAddress, &e.UserAgent, &e.Success, &e.Details, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("lese auditrad: %w", err)
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// countAuditEvents teller rader som matcher filteret — pagineringen må vise
// antall treff, ikke antall rader i tabellen.
func countAuditEvents(ctx context.Context, sqldb *sql.DB, f auditFilter) (int64, error) {
	where, args := buildAuditQuery(f)
	var n int64
	err := sqldb.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_events"+where, args...).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("telle auditlogg: %w", err)
	}
	return n, nil
}

// loadAuditChoices henter de distinkte verdiene for multi-valg-kolonnene.
func loadAuditChoices(ctx context.Context, sqldb *sql.DB) (auditChoices, error) {
	var c auditChoices
	var err error
	if c.Events, err = distinctValues(ctx, sqldb, "event_type"); err != nil {
		return c, err
	}
	if c.Methods, err = distinctValues(ctx, sqldb, "auth_method"); err != nil {
		return c, err
	}
	if c.Services, err = distinctValues(ctx, sqldb, "service_id"); err != nil {
		return c, err
	}
	return c, nil
}

// distinctValues lister verdiene i en kolonne sortert, med auditNoneValue til
// slutt dersom noen rader har NULL der.
func distinctValues(ctx context.Context, sqldb *sql.DB, column string) ([]string, error) {
	rows, err := sqldb.QueryContext(ctx,
		"SELECT DISTINCT "+column+" FROM audit_events ORDER BY "+column)
	if err != nil {
		return nil, fmt.Errorf("hente verdier for %s: %w", column, err)
	}
	defer rows.Close()

	var values []string
	hasNull := false
	for rows.Next() {
		var v *string
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("lese verdi for %s: %w", column, err)
		}
		if v == nil || *v == "" {
			hasNull = true
			continue
		}
		values = append(values, *v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if hasNull {
		values = append(values, auditNoneValue)
	}
	return values, nil
}
