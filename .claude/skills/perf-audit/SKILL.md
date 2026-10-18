---
name: perf-audit
description: >
  Systematisk ytelsesaudit og -fikser for kauth — Go 1.24 CGO-fri binær med chi + modernc.org/sqlite (WAL) på Raspberry Pi 5 bak Cloudflare Tunnel, som systemd-tjeneste med GOMEMLIMIT og cgroup-tak.
  Analyserer og implementerer optimaliseringer på alle lag: latens på /token, login og callback, RS256-signering, SQLite-låsing og busy_timeout, indeksbruk, bakgrunnsjobber, minne/GC, kall mot Google/Microsoft/SMTP og levering av login-sider.
  Bruk denne skillen ved treg innlogging, treg /token-refresh, SQLITE_BUSY-feil, høy minnebruk eller OOM på Pi-en, voksende database, eller generell optimalisering.
user-invocable: true
argument-hint: "[område eller symptom]"
---

# Ytelsesaudit — kauth

## Overordnet strategi

**Mål før du fikser.** kauth kjører på én Raspberry Pi 5 som én Go-prosess med én SQLite-fil. Go-koden selv er sjelden flaskehalsen — de fleste «trege» opplevelser er ventetid på Google/Microsoft (token-utveksling, JWKS/discovery), SMTP for magic link, en skriver som venter på SQLite-låsen, eller nettverkshoppet gjennom Cloudflare Tunnel. Gjett aldri hvilken.

Rekkefølge: **mål → finn dominerende ledd → fiks ett ledd → mål på nytt.** En optimalisering uten før/etter-tall er en påstand, ikke et resultat.

---

## Fase 1: Audit

Gå gjennom områdene som er relevante for symptomet. Ikke audit alt hver gang.

### 1a. Varme stier: `/token`, `/api/me`, JWKS

`/token` (refresh) er det tjenestene kaller oftest — det skjer hver gang et access-token (default `PT15M`) utløper, for hver aktiv bruker.

- Refresh-rotasjon er én lese- og flere skriveoperasjoner (marker brukt, sett inn nytt) — sjekk at de skjer i én transaksjon, ikke flere runder
- RS256-signering koster ~1–2 ms på Pi 5 med 2048-bit nøkkel. Mål før du antar at det er et problem; 4096-bit nøkkel vil merkes
- `/.well-known/jwks.json` og discovery er statiske gitt nøkkelparet — svarene kan bygges én gang og serveres med `Cache-Control`
- Service-oppslag skal gå mot `service.Registry`-cachen, aldri mot DB per request

### 1b. SQLite: låsing, busy_timeout og indekser (`internal/db/`, `internal/db/query/`)

DSN setter `journal_mode(WAL)`, `foreign_keys(1)` og `busy_timeout(5000)` (`internal/db/db.go`). WAL gir samtidige lesere, men fortsatt **én skriver om gangen**.

- `SQLITE_BUSY`/`database is locked` i loggen betyr at en skriver ventet > 5 s — finn transaksjonen som holder låsen, ikke øk timeouten blindt
- Lange skrivetransaksjoner: cleanup-jobben sletter i én DELETE — på en stor `audit_events` kan den blokkere innlogginger. Vurder batching (`LIMIT` i løkke)
- Audit-events skrives synkront per innlogging og admin-operasjon — det er én ekstra skriving i login-stien
- Kjør `EXPLAIN QUERY PLAN` på spørringene i den trege ruten — se etter `SCAN` der du forventet `SEARCH ... USING INDEX`
- Admin-panelets audit-visning filtrerer på e-post, service og tidsrom: indeksen `(service_id, created_at)` hjelper bare når service er med i filteret
- `database/sql`-poolen: flere åpne koblinger gir parallelle lesere, men skrivere serialiseres uansett. `concurrency_test.go` dekker dette — kjør den med `-race`
- WAL-filen: vokser `data/*.db-wal` uten å krympe, kjører ikke checkpoint (typisk pga. en evig åpen lesetransaksjon)

### 1c. Bakgrunnsjobber (`internal/jobs/cleanup.go`)

Tre tickere (magic tokens, refresh tokens, audit events), hver time.

- Hvor lang tid tar hver kjøring på prod-størrelse? Logg varighet og antall slettede rader
- Kolliderer jobben med trafikktopper? Én times intervall er fint; kjøring ved oppstart samtidig med `Warmup` kan gi låsekonkurranse
- Vokser `refresh_tokens` likevel? Sjekk at slettingen faktisk lykkes (jf. FK-feilen som 005-migrasjonen rettet)

### 1d. Eksterne kall: Google, Microsoft, SMTP

For brukeren er dette som regel *hele* den opplevde ventetiden i login-flyten.

- `oidc.NewProvider` gjør discovery mot Google — skjer det per request eller én gang ved oppstart? Per request koster et ekstra rundtur-kall
- JWKS-oppslag hos Microsoft (`NewRemoteKeySet`) cacher nøkler — verifiser at key-set-objektet gjenbrukes og ikke opprettes per callback
- Token-utveksling i callback: sett eksplisitt timeout på HTTP-klienten (`context.WithTimeout`) — standardklienten har ingen
- Magic link: SMTP-sending i request-tråden gjør responsen avhengig av mailserveren. Mål med `KAUTH_SMTP_MOCK=false` mot ekte server
- Rate-limiteren for magic link (3/15 min/e-post) — er den i minnet med ubegrenset vekst, eller ryddes gamle nøkler?

### 1e. Minne og GC

systemd-enheten setter `GOMEMLIMIT=96MiB`, `MemoryHigh=112M`, `MemoryMax=128M`. Tomgang ligger rundt 21 MB, last 30–50 MB.

- `systemctl status kauth` og `systemctl show kauth -p MemoryCurrent` over tid — jevn vekst er lekkasje
- Når heap nærmer seg GOMEMLIMIT, kjører GC aggressivt og CPU-bruken stiger — symptomet er høy CPU, ikke OOM
- Kilder til vekst: in-memory rate-limiter-map, cache av alle services (inkl. `bg_css`/`logo_html`), parsede maler, store request-bodies uten `http.MaxBytesReader`
- Profilering: midlertidig `net/http/pprof` bak admin eller kun på localhost — aldri eksponert gjennom tunnelen, og fjernes etterpå

### 1f. Login-sider og statiske filer (`templates/`, `static/`)

- Maler parses ved oppstart — verifiser at ingen handler kaller `template.ParseFiles` per request
- Bakgrunnsbilder i `static/` (jpg/webp) kan være flere hundre KB — de dominerer lastetiden på login-siden over mobilnett. Sjekk størrelse og `Cache-Control`
- Inline CSS per tjeneste (`bg_css`, `accent_color`) er billig; eksterne fonter eller skript er det ikke

### 1g. Nettverk og Pi-ressurser

- Cloudflare Tunnel legger på et hopp — mål lokalt (`curl -w '%{time_total}' http://localhost:8083/...`) og utenfra, og sammenlign
- `journalctl -u kauth` for gjentatte feil som koster tid uten å feile synlig (slog skriver strukturert)
- `vcgencmd measure_temp` og throttling — en varm Pi klokker ned

---

## Fase 2: Presentasjon av funn

Presenter funn FØR du implementerer. Format:

```markdown
## Ytelsesaudit — [område]

### Målt utgangspunkt
| Operasjon | Tid | Metode |
|-----------|-----|--------|
| POST /token (refresh) | 38 ms p50 / 410 ms p95 | hey -n 500 mot localhost |

### Funn
| # | Område | Symptom | Antatt årsak | Estimert gevinst | Risiko |
|---|--------|---------|--------------|------------------|--------|
| P1 | SQLite | p95-topper på /token | cleanup-DELETE på audit_events holder skrivelåsen | ~350 ms p95 | Lav |

### Anbefalt rekkefølge
1. P1 — størst gevinst, lavest risiko
```

Ranger etter **gevinst delt på risiko**, ikke etter hvor interessant problemet er.

---

## Fase 3: Implementering

- Fiks **ett** ledd om gangen, og mål mellom hver
- Hold deg innenfor det som ble presentert i fase 2 — en ytelsesaudit er ikke en anledning til å refaktorere
- Ytelsesfikser som endrer atferd (lengre token-TTL, caching av svar som avhenger av bruker, mindre streng refresh-rotasjon) skal gjennom vanlig feature-lifecycle og security-review, ikke smugles inn som «optimalisering»
- Endringer i skjema eller indekser: kjør migration-guard
- Nye avhengigheter for profilering eller benchmarking: kjør dependency-guard, og fjern dem igjen etterpå hvis de kun var for målingen

---

## Fase 4: Verifisering

- Kjør nøyaktig samme måling som i fase 2 og oppgi før/etter-tall
- `CGO_ENABLED=0 go test ./...` og `go test -race ./...` skal fortsatt være grønne — en optimalisering som bryter en test er en regresjon
- Bruk `go test -bench` for isolerte endringer (signering, parsing); bruk ende-til-ende-måling for alt som involverer DB eller nettverk
- Ved DB-endringer: verifiser mot en kopi av prod-DB fra backup i realistisk størrelse, ikke mot en tom testdatabase

---

## Hva du IKKE skal gjøre

- **Ikke optimaliser uten måling.** «Dette ser tregt ut» er ikke et funn
- **Ikke bytt database, legg til Redis eller innfør en cache-tjeneste** på eget initiativ — det bryter produktpremisset om én binær og hører hjemme i solution-architect
- **Ikke restart tjenesten mens bruker tester** — prod kjører på samme maskin, og en restart logger ikke ut brukere men avbryter pågående login-flyter
- **Ikke cache deg ut av et korrekthetsproblem.** Caching av token- eller brukerdata på tvers av tjenester er en lekkasjerisiko, ikke en ytelsesfiks
- **Ikke svekk sikkerhet for fart**: kortere nøkler, lavere bcrypt-cost, utelatt signaturverifikasjon eller lengre access-token-TTL er ikke ytelsesfikser
- **Ikke fjern indekser** uten å ha sett `EXPLAIN QUERY PLAN` for spørringene som kunne brukt dem
- **Ikke øk GOMEMLIMIT/MemoryMax** for å skjule en lekkasje

---

## Kontekst: kjent infrastruktur

| Lag | Detalj |
|-----|--------|
| Maskin | Raspberry Pi 5 (arm64), system-service `kauth.service`, ingen Docker i prod |
| Server | Én Go-prosess, chi-router, `net/http`, port `KAUTH_HTTP_PORT` (default 8080; prod 8083) |
| Minne | `GOMEMLIMIT=96MiB`, `MemoryHigh=112M`, `MemoryMax=128M` |
| Database | SQLite via modernc.org/sqlite, WAL, `busy_timeout(5000)`, `foreign_keys(1)` |
| Kryptografi | RS256 (golang-jwt), bcrypt kun for legacy-passord |
| Jobber | `internal/jobs` cleanup hver time (magic, refresh, audit 90 d) |
| Nett | Cloudflare Tunnel foran, TLS termineres hos Cloudflare |
| Eksternt | Google OIDC, Microsoft Entra (`/common`), SMTP — alle med nettverkslatens |

Ved tvil om et tall: mål det. Verktøyene finnes på maskinen eller i Go-verktøykjeden (`curl -w`, `journalctl -u kauth`, `EXPLAIN QUERY PLAN`, `go test -bench`, `go tool pprof`).
