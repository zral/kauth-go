# migration-guard — kauth

Kjøres ved endringer i `internal/db/migrations/` (goose), `internal/db/query/` (sqlc) eller `sqlc.yaml`.

## Kontekst

- **Database:** SQLite via `modernc.org/sqlite` (CGO-fri), WAL, `foreign_keys(1)`, `busy_timeout(5000)` — satt i DSN i `internal/db/db.go`
- **Migrasjoner:** goose, nummerert `internal/db/migrations/NNN_<navn>.sql` med `-- +goose Up` / `-- +goose Down`. Hver migrasjon MÅ ha en Down-seksjon; for irreversible endringer forklares tapet i en kommentar i Down
- **Queries:** `internal/db/query/<tabell>.sql` → `make sqlc` → `internal/db/gen/` (aldri håndredigert). sqlc leser skjemaet fra migrasjonsmappen, så en migrasjon sqlc ikke forstår knekker genereringen. `emit_pointers_for_null_types` gir `*string` for nullable
- **Kjøring:** `db.Open()` kjører ventende migrasjoner automatisk ved oppstart — prod oppgraderes når ny binær restartes
- **Transaksjon:** goose kjører hver fil i transaksjon; `-- +goose NO TRANSACTION` krever eksplisitt begrunnelse
- **Tabeller:** services, users, magic_tokens, refresh_tokens, audit_events
- **Produksjonsdata:** brukerkontoer, roller/org og aktive refresh-token-familier for alle tjenester. Tap av `services` eller `users` låser alle ut; tap av `refresh_tokens` logger alle ut
- **Backup:** `scripts/backup-kauth-go.sh` (cron 03:00). Kjør manuell backup før deploy av risikable migrasjoner

## Kauth-spesifikke sjekker

- **Rebuild-referanse:** `005_refresh_token_parent_on_delete.sql` — riktig mønster, FK-rekkefølge (`ORDER BY id`, foreldreløse pekere nulles først) og Down som dokumenterer hva som ikke kommer tilbake
- **ON DELETE:** `NO ACTION` på selvreferanse kan blokkere oppryddingsjobben i `internal/jobs` (jf. 005)
- **Indeksbygging:** `audit_events` kan være stor — ny indeks låser skrivere mens den bygges
- **CHECK:** eksisterende data må tåle nye constraints (f.eks. `length(token_hash) = 64`)
- **Unik:** e-post, domain, auth_host
- **Nye `services`-kolonner:** default må gi uendret oppførsel for eksisterende tjenester (auth-metoder, claims, TTL)
- **CASCADE / SET NULL:** sletting av service eller bruker skal ikke fjerne audit-spor eller tokens uventet
- **Persondata:** sjekk at cleanup-jobben i `internal/jobs` dekker nye kolonner
- Go-kode som bruker nye kolonner: `internal/service/registry.go` og handlere

## Verifisering

```bash
make sqlc && git diff --exit-code internal/db/gen/   # gen/ i synk
CGO_ENABLED=0 go test ./internal/db/...               # migrasjoner kjører på tom DB
```

Test Up mot en kopi av prod-DB (fra backup) for rebuilds og datamigreringer, og test Down → Up.
