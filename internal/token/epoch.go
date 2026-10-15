package token

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/zral/kauth-go/internal/db/gen"
)

const (
	epochLayoutRFC3339 = "2006-01-02T15:04:05Z"
	epochLayoutSQLite  = "2006-01-02 15:04:05"
)

// ParseEpoch tolker et epoke-tidsstempel: RFC 3339 med Z (det kauth skriver) og
// SQLite datetime() (UTC), slik at seed-SQL i tester og eval ikke låser ute.
// Preflight bruker samme funksjon, så skriptet og runtime ikke kan gli fra hverandre.
func ParseEpoch(s string) (time.Time, error) {
	if t, err := time.Parse(epochLayoutRFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(epochLayoutSQLite, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("ukjent tidsformat for epoke")
}

// EmailEpoch er tidspunktet brukerens nåværende e-post ble brukerens:
// coalesce(email_changed_at, created_at).
func EmailEpoch(u gen.User) (time.Time, error) {
	raw := u.CreatedAt
	if u.EmailChangedAt != nil {
		raw = *u.EmailChangedAt
	}
	return ParseEpoch(raw)
}

// IssuedAfterEmailEpoch er fail-closed: manglende iat eller en epoke som ikke
// kan tolkes gir false. Et token utstedt før adressen kom til brukeren kan ha
// tilhørt en tidligere eier av adressen. Sekundnivå, så et token utstedt i
// samme sekund som epoken godtas.
func IssuedAfterEmailEpoch(c *Claims, u gen.User) bool {
	if c == nil || c.IssuedAt == nil {
		return false
	}
	epoch, err := EmailEpoch(u)
	if err != nil {
		// Bruker-ID, ikke e-post, i loggen.
		slog.Error("e-postepoke kan ikke tolkes", "user_id", u.ID)
		return false
	}
	return c.IssuedAt.Unix() >= epoch.Unix()
}
