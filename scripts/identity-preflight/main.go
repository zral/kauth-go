// identity-preflight kjører migrasjonene (010 stabil identitet, 011 admin-identitet)
// mot en KOPI av produksjonsdatabasen og skriver en rapport uten e-postadresser.
// Bruk via scripts/identity-preflight.sh, som lager kopien med sqlite3 .backup.
// Kjøres aldri mot en live-database: db.Open migrerer.
package main

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/token"
	_ "modernc.org/sqlite"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "bruk: identity-preflight <kopi.db>")
		os.Exit(2)
	}
	os.Exit(run(os.Args[1]))
}

func run(path string) int {
	if _, err := os.Stat(path); err != nil {
		fmt.Fprintln(os.Stderr, "finner ikke kopien:", err)
		return 2
	}

	// Egen forbindelse for vakt-sjekken før migrasjonen: db.Open migrerer
	// umiddelbart, og da er det for sent å liste de avvikende radene.
	pre, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		fmt.Fprintln(os.Stderr, "åpne kopi:", err)
		return 2
	}
	bad, err := guardViolations(pre)
	pre.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, "vakt-spørring:", err)
		return 2
	}

	fmt.Println("== identity-preflight (migrasjon 010 og 011) ==")
	if len(bad) > 0 {
		fmt.Printf("vakt: FEIL, %d bruker(e) med ikke-normalisert eller ikke-ASCII e-post\n", len(bad))
		fmt.Printf("  bruker-ID-er: %s\n", strings.Join(bad, ", "))
		fmt.Println("  Migrasjonen vil avvise. Rett radene manuelt og kjør på nytt.")
		return 1
	}
	fmt.Println("vakt: OK (alle e-poster er normaliserte og ASCII)")

	sqldb, _, err := db.Open(path)
	if err != nil {
		fmt.Println("migrasjon: FEIL ved db.Open (se feilmelding på stderr)")
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer sqldb.Close()

	var ver int64
	must(sqldb.QueryRow(`SELECT max(version_id) FROM goose_db_version WHERE is_applied = 1`).Scan(&ver))
	fmt.Printf("migrasjon: OK, goose-versjon %d\n", ver)

	var users, pubIDs, distinctPub, validPub int
	must(sqldb.QueryRow(`SELECT count(*), count(public_id), count(DISTINCT public_id),
		coalesce(sum(public_id GLOB '????????-????-4???-[89ab]???-????????????'), 0) FROM users`).
		Scan(&users, &pubIDs, &distinctPub, &validPub))
	fmt.Printf("users: %d, med public_id: %d, unike: %d, UUID v4-format: %d\n", users, pubIDs, distinctPub, validPub)

	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	var rtActiveNull, rtExpiredNull, rtTotal int
	must(sqldb.QueryRow(`SELECT count(*),
		coalesce(sum(user_id IS NULL AND used = 0 AND revoked = 0 AND expires_at > ?), 0),
		coalesce(sum(user_id IS NULL AND NOT (used = 0 AND revoked = 0 AND expires_at > ?)), 0)
		FROM refresh_tokens`, now, now).Scan(&rtTotal, &rtActiveNull, &rtExpiredNull))
	fmt.Printf("refresh_tokens: %d totalt; uten user_id: %d aktive, %d utløpt/brukt/revokert\n", rtTotal, rtActiveNull, rtExpiredNull)

	var acTotal, acActiveNull, acExpiredNull int
	must(sqldb.QueryRow(`SELECT count(*),
		coalesce(sum(user_id IS NULL AND used = 0 AND expires_at > ?), 0),
		coalesce(sum(user_id IS NULL AND NOT (used = 0 AND expires_at > ?)), 0)
		FROM authorization_codes`, now, now).Scan(&acTotal, &acActiveNull, &acExpiredNull))
	fmt.Printf("authorization_codes: %d totalt; uten user_id: %d aktive, %d utløpt/brukt\n", acTotal, acActiveNull, acExpiredNull)

	// Aktive rader med ikke-normalisert e-post: de får user_id via lower(trim()),
	// men aktører og logger ser fortsatt den gamle skrivemåten. Bare antall.
	var rtMixed, acMixed int
	must(sqldb.QueryRow(`SELECT count(*) FROM refresh_tokens
		WHERE used = 0 AND revoked = 0 AND expires_at > ? AND email <> lower(trim(email))`, now).Scan(&rtMixed))
	must(sqldb.QueryRow(`SELECT count(*) FROM authorization_codes
		WHERE used = 0 AND expires_at > ? AND email <> lower(trim(email))`, now).Scan(&acMixed))
	fmt.Printf("aktive rader med ikke-normalisert e-post: refresh_tokens %d, authorization_codes %d\n", rtMixed, acMixed)

	var badSvc int
	must(sqldb.QueryRow(`SELECT count(*) FROM services WHERE sub_format <> 'email' OR auto_link <> 1`).Scan(&badSvc))
	fmt.Printf("services med annet enn sub_format=email/auto_link=1: %d\n", badSvc)

	// 012: admin-bindingen skal følge admin_ok-identitetene, og epoken
	// (coalesce(email_changed_at, created_at)) må kunne tolkes av
	// token.EmailEpoch, ellers låses brukeren ute (fail-closed).
	var boundUsers, adminOKUsers, adminOKUnbound, kongeUnbound int
	must(sqldb.QueryRow(`SELECT count(*) FROM users WHERE admin_bound_at IS NOT NULL`).Scan(&boundUsers))
	must(sqldb.QueryRow(`SELECT count(DISTINCT user_id) FROM user_identities WHERE admin_ok = 1`).Scan(&adminOKUsers))
	must(sqldb.QueryRow(`SELECT count(*) FROM users WHERE admin_bound_at IS NULL
		AND id IN (SELECT user_id FROM user_identities WHERE admin_ok = 1)`).Scan(&adminOKUnbound))
	must(sqldb.QueryRow(`SELECT count(*) FROM users WHERE admin_bound_at IS NULL
		AND ',' || replace(roles, ' ', '') || ',' LIKE '%,konge,%'`).Scan(&kongeUnbound))
	fmt.Printf("admin_bound_at: %d bruker(e) bundet, %d bruker(e) med admin_ok-identitet, %d med admin_ok uten binding\n", boundUsers, adminOKUsers, adminOKUnbound)
	fmt.Printf("konge uten admin_bound_at: %d\n", kongeUnbound)

	badEpoch, futureEpoch, err := unparseableEpochs(sqldb)
	must(err)
	fmt.Printf("epoker i fremtiden: %d\n", futureEpoch)
	fmt.Printf("users.created_at/email_changed_at som ikke kan tolkes som epoke: %d\n", badEpoch)

	var fkViol int
	rows, err := sqldb.Query(`PRAGMA foreign_key_check`)
	must(err)
	for rows.Next() {
		fkViol++
	}
	rows.Close()
	fmt.Printf("foreign_key_check: %d brudd\n", fkViol)

	var integrity string
	must(sqldb.QueryRow(`PRAGMA integrity_check`).Scan(&integrity))
	fmt.Printf("integrity_check: %s\n", integrity)

	if pubIDs != users || distinctPub != users || validPub != users || fkViol > 0 || integrity != "ok" {
		fmt.Println("RESULTAT: FEIL")
		return 1
	}
	// En aktiv rad uten user_id revokeres ikke lenger på e-post (D8a). Kjør
	// backfill-UPDATE-en fra migrasjon 010 på nytt før deploy hvis tallet er over 0.
	if boundUsers != adminOKUsers || adminOKUnbound > 0 || badEpoch > 0 || futureEpoch > 0 || rtActiveNull > 0 {
		fmt.Println("RESULTAT: FEIL (admin-binding, epoke eller refresh uten user_id avviker fra forventet)")
		return 1
	}
	if rtMixed > 0 || acMixed > 0 {
		fmt.Println("RESULTAT: ADVARSEL (aktive rader med ikke-normalisert e-post)")
		return 0
	}
	fmt.Println("RESULTAT: OK")
	return 0
}

// guardViolations speiler vakten i migrasjon 010 og returnerer bare ID-er.
func guardViolations(d *sql.DB) ([]string, error) {
	rows, err := d.Query(`SELECT id FROM users WHERE email <> lower(trim(email)) OR email GLOB '*[^ -~]*' ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, fmt.Sprint(id))
	}
	return ids, rows.Err()
}

// unparseableEpochs teller epoker som token.EmailEpoch ville avvist, og epoker i fremtiden. Formatene
// bruker selve runtime-parseren (token.ParseEpoch), så de ikke kan gli fra hverandre.
func unparseableEpochs(d *sql.DB) (bad, future int, err error) {
	rows, err := d.Query(`SELECT coalesce(email_changed_at, created_at) FROM users`)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	now := time.Now().UTC()
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return 0, 0, err
		}
		t, perr := token.ParseEpoch(v)
		if perr != nil {
			bad++
		} else if t.After(now) {
			// En epoke i fremtiden avviser alle tokens til tiden er inne.
			future++
		}
	}
	return bad, future, rows.Err()
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "preflight:", err)
		os.Exit(1)
	}
}
