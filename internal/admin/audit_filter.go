package admin

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// auditNoneValue er sentinel-verdien for rader der kolonnen er NULL. Uten den
// ville "huk av alt" skjult hendelser som mangler metode eller tjeneste.
const auditNoneValue = "__none__"

// auditFilter er de parsede filterparameterne fra querystrengen.
type auditFilter struct {
	From     string // dato YYYY-MM-DD, inklusiv
	To       string // dato YYYY-MM-DD, inklusiv
	Email    string // substring
	IP       string // substring
	Details  string // substring
	Events   []string
	Methods  []string
	Services []string
	OK       []string // "1" og/eller "0"
}

// parseAuditFilter leser filterparametere fra querystrengen.
func parseAuditFilter(r *http.Request) auditFilter {
	q := r.URL.Query()
	return auditFilter{
		From:     strings.TrimSpace(q.Get("from")),
		To:       strings.TrimSpace(q.Get("to")),
		Email:    strings.TrimSpace(q.Get("email")),
		IP:       strings.TrimSpace(q.Get("ip")),
		Details:  strings.TrimSpace(q.Get("details")),
		Events:   q["event"],
		Methods:  q["method"],
		Services: q["service"],
		OK:       q["ok"],
	}
}

// QueryString gjenskaper filteret som querystring, slik at paginering og
// CSV-eksport kan bære med seg alle valg uten å bygges opp i templaten.
func (f auditFilter) QueryString() string {
	v := url.Values{}
	for key, val := range map[string]string{
		"from": f.From, "to": f.To, "email": f.Email, "ip": f.IP, "details": f.Details,
	} {
		if val != "" {
			v.Set(key, val)
		}
	}
	for key, vals := range map[string][]string{
		"event": f.Events, "method": f.Methods, "service": f.Services, "ok": f.OK,
	} {
		for _, s := range vals {
			if strings.TrimSpace(s) != "" {
				v.Add(key, s)
			}
		}
	}
	return v.Encode()
}

// Selected sier om en verdi er huket av i en gruppe. Tom gruppe = alt med.
func (f auditFilter) Selected(group []string, value string) bool {
	if len(cleanChoices(group)) == 0 {
		return true
	}
	for _, s := range group {
		if s == value {
			return true
		}
	}
	return false
}

// buildAuditQuery bygger WHERE-delen av auditspørringen med bundne parametere.
// Returnerer tom streng når ingenting er filtrert på.
func buildAuditQuery(f auditFilter) (string, []any) {
	var clauses []string
	var args []any

	if ts, ok := parseDayStart(f.From); ok {
		clauses = append(clauses, "created_at >= ?")
		args = append(args, ts)
	}
	if ts, ok := parseDayEnd(f.To); ok {
		clauses = append(clauses, "created_at <= ?")
		args = append(args, ts)
	}

	for _, sel := range []struct {
		column string
		values []string
	}{
		{"event_type", f.Events},
		{"auth_method", f.Methods},
		{"service_id", f.Services},
	} {
		if clause, a := choiceClause(sel.column, sel.values); clause != "" {
			clauses = append(clauses, clause)
			args = append(args, a...)
		}
	}

	for _, sub := range []struct {
		column string
		value  string
	}{
		{"email", f.Email},
		{"ip_address", f.IP},
		{"details", f.Details},
	} {
		if sub.value == "" {
			continue
		}
		clauses = append(clauses, sub.column+` LIKE ? ESCAPE '\'`)
		args = append(args, "%"+escapeLike(sub.value)+"%")
	}

	if clause, a := successClause(f.OK); clause != "" {
		clauses = append(clauses, clause)
		args = append(args, a...)
	}

	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// choiceClause lager IN-listen for en multi-valg-kolonne, med NULL-håndtering.
func choiceClause(column string, values []string) (string, []any) {
	vals := cleanChoices(values)
	if len(vals) == 0 {
		return "", nil
	}

	includeNull := false
	args := make([]any, 0, len(vals))
	for _, v := range vals {
		if v == auditNoneValue {
			includeNull = true
			continue
		}
		args = append(args, v)
	}

	switch {
	case len(args) == 0:
		return column + " IS NULL", nil
	case includeNull:
		return "(" + column + " IN (" + placeholders(len(args)) + ") OR " + column + " IS NULL)", args
	default:
		return column + " IN (" + placeholders(len(args)) + ")", args
	}
}

// successClause filtrerer på success-kolonnen; ikke-numeriske verdier ignoreres.
func successClause(values []string) (string, []any) {
	var args []any
	for _, v := range cleanChoices(values) {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			continue
		}
		args = append(args, n)
	}
	if len(args) == 0 {
		return "", nil
	}
	return "success IN (" + placeholders(len(args)) + ")", args
}

func cleanChoices(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// escapeLike nøytraliserer LIKE-metategn slik at søket blir rent substring-søk.
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

func parseDayStart(s string) (string, bool) {
	d, err := time.Parse("2006-01-02", s)
	if err != nil {
		return "", false
	}
	return d.Format("2006-01-02") + "T00:00:00Z", true
}

func parseDayEnd(s string) (string, bool) {
	d, err := time.Parse("2006-01-02", s)
	if err != nil {
		return "", false
	}
	return d.Format("2006-01-02") + "T23:59:59Z", true
}
