package admin

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
)

// setupAuditDB seeder en liten, forutsigbar auditlogg.
func setupAuditDB(t *testing.T) *sql.DB {
	t.Helper()
	ctx := context.Background()

	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })

	str := func(s string) *string { return &s }
	events := []gen.InsertAuditEventParams{
		{EventType: "login_success", AuthMethod: str("google"), Email: str("lars@spekto.no"),
			ServiceID: str("spekto"), IpAddress: str("10.0.0.1"), Success: 1,
			Details: str("ok"), CreatedAt: "2026-08-01T09:00:00Z"},
		{EventType: "login_failed", AuthMethod: str("password"), Email: str("kari@pov.no"),
			ServiceID: str("pov"), IpAddress: str("10.0.0.2"), Success: 0,
			Details: str("invalid password"), CreatedAt: "2026-08-15T12:00:00Z"},
		{EventType: "login_success", AuthMethod: str("password"), Email: str("kari@pov.no"),
			ServiceID: str("pov"), IpAddress: str("192.168.1.5"), Success: 1,
			CreatedAt: "2026-08-20T08:30:00Z"},
		// Uten metode og tjeneste — dekker NULL-tilfellet.
		{EventType: "refresh_token_issued", Email: str("lars@spekto.no"),
			IpAddress: str("10.0.0.1"), Success: 1, CreatedAt: "2026-08-30T23:59:00Z"},
	}
	for _, e := range events {
		require.NoError(t, q.InsertAuditEvent(ctx, e))
	}
	return sqldb
}

func TestQueryAuditEvents_NoFilter_ReturnsAllNewestFirst(t *testing.T) {
	sqldb := setupAuditDB(t)
	events, err := queryAuditEvents(context.Background(), sqldb, auditFilter{}, 50, 0)
	require.NoError(t, err)
	require.Len(t, events, 4)
	assert.Equal(t, "refresh_token_issued", events[0].EventType)
	assert.Equal(t, "login_success", events[3].EventType)
	assert.Equal(t, "2026-08-01T09:00:00Z", events[3].CreatedAt)
}

func TestQueryAuditEvents_EventMultiSelect_FiltersRows(t *testing.T) {
	sqldb := setupAuditDB(t)
	f := auditFilter{Events: []string{"login_failed", "refresh_token_issued"}}
	events, err := queryAuditEvents(context.Background(), sqldb, f, 50, 0)
	require.NoError(t, err)
	require.Len(t, events, 2)
	assert.Equal(t, "refresh_token_issued", events[0].EventType)
	assert.Equal(t, "login_failed", events[1].EventType)
}

func TestQueryAuditEvents_EmailSubstring_MatchesPartial(t *testing.T) {
	sqldb := setupAuditDB(t)
	events, err := queryAuditEvents(context.Background(), sqldb, auditFilter{Email: "@pov.no"}, 50, 0)
	require.NoError(t, err)
	assert.Len(t, events, 2)
}

func TestQueryAuditEvents_DateRange_IsInclusive(t *testing.T) {
	sqldb := setupAuditDB(t)
	f := auditFilter{From: "2026-08-15", To: "2026-08-20"}
	events, err := queryAuditEvents(context.Background(), sqldb, f, 50, 0)
	require.NoError(t, err)
	assert.Len(t, events, 2)
}

func TestQueryAuditEvents_CombinedFilters_AreAnded(t *testing.T) {
	sqldb := setupAuditDB(t)
	f := auditFilter{Services: []string{"pov"}, OK: []string{"0"}, Details: "invalid"}
	events, err := queryAuditEvents(context.Background(), sqldb, f, 50, 0)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "login_failed", events[0].EventType)
}

func TestQueryAuditEvents_NoneSentinel_FindsRowsWithoutService(t *testing.T) {
	sqldb := setupAuditDB(t)
	f := auditFilter{Services: []string{auditNoneValue}}
	events, err := queryAuditEvents(context.Background(), sqldb, f, 50, 0)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "refresh_token_issued", events[0].EventType)
}

func TestQueryAuditEvents_LikeWildcard_IsTakenLiterally(t *testing.T) {
	sqldb := setupAuditDB(t)
	// "%" skal ikke oppføre seg som jokertegn — ingen rad inneholder tegnet.
	events, err := queryAuditEvents(context.Background(), sqldb, auditFilter{Email: "%"}, 50, 0)
	require.NoError(t, err)
	assert.Empty(t, events)
}

func TestQueryAuditEvents_Offset_Paginates(t *testing.T) {
	sqldb := setupAuditDB(t)
	events, err := queryAuditEvents(context.Background(), sqldb, auditFilter{}, 2, 2)
	require.NoError(t, err)
	require.Len(t, events, 2)
	assert.Equal(t, "login_failed", events[0].EventType)
}

func TestCountAuditEvents_RespectsFilter(t *testing.T) {
	sqldb := setupAuditDB(t)
	ctx := context.Background()

	all, err := countAuditEvents(ctx, sqldb, auditFilter{})
	require.NoError(t, err)
	assert.Equal(t, int64(4), all)

	filtered, err := countAuditEvents(ctx, sqldb, auditFilter{Email: "@pov.no"})
	require.NoError(t, err)
	assert.Equal(t, int64(2), filtered)
}

func TestLoadAuditChoices_ReturnsSortedDistinctValues(t *testing.T) {
	sqldb := setupAuditDB(t)
	choices, err := loadAuditChoices(context.Background(), sqldb)
	require.NoError(t, err)
	assert.Equal(t, []string{"login_failed", "login_success", "refresh_token_issued"}, choices.Events)
}

func TestLoadAuditChoices_AppendsNoneSentinelWhenNullsExist(t *testing.T) {
	sqldb := setupAuditDB(t)
	choices, err := loadAuditChoices(context.Background(), sqldb)
	require.NoError(t, err)
	assert.Equal(t, []string{"google", "password", auditNoneValue}, choices.Methods)
	assert.Equal(t, []string{"pov", "spekto", auditNoneValue}, choices.Services)
}
