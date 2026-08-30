package admin

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildAuditQuery_EmptyFilter_NoWhere(t *testing.T) {
	where, args := buildAuditQuery(auditFilter{})
	assert.Equal(t, "", where)
	assert.Empty(t, args)
}

func TestBuildAuditQuery_From_LowerBoundAtMidnight(t *testing.T) {
	where, args := buildAuditQuery(auditFilter{From: "2026-08-01"})
	assert.Equal(t, " WHERE created_at >= ?", where)
	assert.Equal(t, []any{"2026-08-01T00:00:00Z"}, args)
}

func TestBuildAuditQuery_To_UpperBoundAtEndOfDay(t *testing.T) {
	where, args := buildAuditQuery(auditFilter{To: "2026-08-30"})
	assert.Equal(t, " WHERE created_at <= ?", where)
	assert.Equal(t, []any{"2026-08-30T23:59:59Z"}, args)
}

func TestBuildAuditQuery_InvalidDate_Ignored(t *testing.T) {
	where, args := buildAuditQuery(auditFilter{From: "i går", To: "2026-13-45"})
	assert.Equal(t, "", where)
	assert.Empty(t, args)
}

func TestBuildAuditQuery_EmailSubstring_UsesLike(t *testing.T) {
	where, args := buildAuditQuery(auditFilter{Email: "spekto.no"})
	assert.Equal(t, ` WHERE email LIKE ? ESCAPE '\'`, where)
	assert.Equal(t, []any{"%spekto.no%"}, args)
}

func TestBuildAuditQuery_SubstringWildcards_AreEscaped(t *testing.T) {
	_, args := buildAuditQuery(auditFilter{Details: `100%_a\b`})
	assert.Equal(t, []any{`%100\%\_a\\b%`}, args)
}

func TestBuildAuditQuery_IPSubstring_UsesLike(t *testing.T) {
	where, args := buildAuditQuery(auditFilter{IP: "84.212."})
	assert.Equal(t, ` WHERE ip_address LIKE ? ESCAPE '\'`, where)
	assert.Equal(t, []any{"%84.212.%"}, args)
}

func TestBuildAuditQuery_MultipleEvents_UsesInList(t *testing.T) {
	where, args := buildAuditQuery(auditFilter{Events: []string{"login_success", "login_failed"}})
	assert.Equal(t, " WHERE event_type IN (?,?)", where)
	assert.Equal(t, []any{"login_success", "login_failed"}, args)
}

func TestBuildAuditQuery_BlankChoices_AreDropped(t *testing.T) {
	where, args := buildAuditQuery(auditFilter{Events: []string{"", "  ", "login_success"}})
	assert.Equal(t, " WHERE event_type IN (?)", where)
	assert.Equal(t, []any{"login_success"}, args)
}

func TestBuildAuditQuery_OnlyBlankChoices_NoWhere(t *testing.T) {
	where, args := buildAuditQuery(auditFilter{Methods: []string{"", "   "}})
	assert.Equal(t, "", where)
	assert.Empty(t, args)
}

func TestBuildAuditQuery_NoneSentinel_MatchesNullAlongsideValues(t *testing.T) {
	where, args := buildAuditQuery(auditFilter{Methods: []string{"google", auditNoneValue}})
	assert.Equal(t, " WHERE (auth_method IN (?) OR auth_method IS NULL)", where)
	assert.Equal(t, []any{"google"}, args)
}

func TestBuildAuditQuery_OnlyNoneSentinel_MatchesNullOnly(t *testing.T) {
	where, args := buildAuditQuery(auditFilter{Services: []string{auditNoneValue}})
	assert.Equal(t, " WHERE service_id IS NULL", where)
	assert.Empty(t, args)
}

func TestBuildAuditQuery_Success_UsesIntegerColumn(t *testing.T) {
	where, args := buildAuditQuery(auditFilter{OK: []string{"1"}})
	assert.Equal(t, " WHERE success IN (?)", where)
	assert.Equal(t, []any{int64(1)}, args)
}

func TestBuildAuditQuery_SuccessNonNumeric_Ignored(t *testing.T) {
	where, args := buildAuditQuery(auditFilter{OK: []string{"ja"}})
	assert.Equal(t, "", where)
	assert.Empty(t, args)
}

func TestBuildAuditQuery_Combination_AndsClausesInStableOrder(t *testing.T) {
	where, args := buildAuditQuery(auditFilter{
		From:     "2026-08-01",
		To:       "2026-08-31",
		Email:    "lars",
		IP:       "10.0.",
		Details:  "invalid",
		Events:   []string{"login_failed"},
		Methods:  []string{"password"},
		Services: []string{"spekto"},
		OK:       []string{"0"},
	})
	assert.Equal(t, " WHERE created_at >= ? AND created_at <= ?"+
		" AND event_type IN (?)"+
		" AND auth_method IN (?)"+
		" AND service_id IN (?)"+
		` AND email LIKE ? ESCAPE '\'`+
		` AND ip_address LIKE ? ESCAPE '\'`+
		` AND details LIKE ? ESCAPE '\'`+
		" AND success IN (?)", where)
	assert.Equal(t, []any{
		"2026-08-01T00:00:00Z", "2026-08-31T23:59:59Z",
		"login_failed", "password", "spekto",
		"%lars%", "%10.0.%", "%invalid%",
		int64(0),
	}, args)
}

func TestActiveCount_EmptyFilter_IsZero(t *testing.T) {
	assert.Equal(t, 0, auditFilter{}.ActiveCount())
}

func TestActiveCount_BlankChoices_DoNotCount(t *testing.T) {
	f := auditFilter{Events: []string{"", "   "}, Methods: []string{}}
	assert.Equal(t, 0, f.ActiveCount())
}

func TestActiveCount_InvalidDate_DoesNotCount(t *testing.T) {
	assert.Equal(t, 0, auditFilter{From: "i går"}.ActiveCount())
}

func TestActiveCount_NonNumericOK_DoesNotCount(t *testing.T) {
	assert.Equal(t, 0, auditFilter{OK: []string{"ja"}}.ActiveCount())
}

func TestActiveCount_DateRange_CountsBothBounds(t *testing.T) {
	assert.Equal(t, 2, auditFilter{From: "2026-08-01", To: "2026-08-31"}.ActiveCount())
}

func TestActiveCount_AllNineFilters(t *testing.T) {
	f := auditFilter{
		From: "2026-08-01", To: "2026-08-31",
		Email: "lars", IP: "10.0.", Details: "invalid",
		Events: []string{"login_failed"}, Methods: []string{"password"},
		Services: []string{"spekto"}, OK: []string{"0"},
	}
	assert.Equal(t, 9, f.ActiveCount())
}

func TestActiveCount_MatchesNumberOfSQLClauses(t *testing.T) {
	// Telleren i skjemaoverskriften må aldri komme i utakt med spørringen.
	f := auditFilter{Email: "lars", Events: []string{"login_failed"}, OK: []string{"1"}}
	where, _ := buildAuditQuery(f)
	assert.Equal(t, 3, f.ActiveCount())
	assert.Equal(t, 2, strings.Count(where, " AND "))
}
