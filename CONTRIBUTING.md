# Bidra til kauth

Kort guide for å sette opp utviklingsoppsett og bidra med endringer.

## Lokal utvikling

```bash
git clone git@github.com:zral/kauth-go.git
cd kauth-go
cp .env.example .env       # fyll inn faktiske verdier
make build                  # bygger bin/kauth
```

Generer RSA-nøkler hvis du ikke har dem:

```bash
mkdir -p secrets
openssl genpkey -algorithm RSA -out secrets/privateKey.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in secrets/privateKey.pem -out secrets/publicKey.pem
```

Generer en OIDC state-secret:

```bash
openssl rand -base64 48
```

Sett den i `.env` som `KAUTH_OIDC_STATE_SECRET`.

For lokal testing uten SMTP, sett `KAUTH_SMTP_MOCK=true` — magic-link logges til stdout.

For lokal HTTP-utvikling, sett `KAUTH_INSECURE_COOKIES=true` — cookies settes uten Secure-flag så de funker over `http://localhost`.

Kjør:

```bash
./bin/kauth
```

Migrasjoner kjører automatisk ved oppstart.

## Tester

```bash
make test                   # CGO_ENABLED=0 go test ./...
```

Testene dekker token-utstedelse, refresh-rotasjon, magic-link-rate-limiting, service-resolver, og admin-middleware. Handler-integrasjonstester for OIDC-flytene er bevisst utelatt — de krever live-providere eller mock-servere.

## Prosjektstruktur

- `cmd/kauth/` — entry point. Konfig, DB-oppstart, router-wiring, graceful shutdown.
- `internal/auth/` — innloggings-handlere (Google, Microsoft, magic-link, password), dispatch, login-side, middleware.
- `internal/token/` — JWT-utstedelse, JWKS, refresh-rotasjon.
- `internal/admin/` — admin-panel: brukere, audit-logg, tjenestekonfig, magic-link- og Google-innlogging for admin.
- `internal/service/` — tjeneste-resolver med cache.
- `internal/db/` — sqlc-generert databaselag mot SQLite.
- `internal/jobs/` — bakgrunnsjobber (cleanup).
- `internal/mail/` — SMTP-sender.
- `internal/audit/` — audit-logging.
- `internal/config/` — env-konfig.

## Databaseendringer

Skjemaendringer:

1. Legg til en ny migrasjon i `internal/db/migrations/` (følg `001_init.sql`-mønsteret med goose-direktiver).
2. Legg til SQL-spørringer i `internal/db/query/<tabell>.sql`.
3. Regenerer Go-koden: `make sqlc` (krever `sqlc` i `$PATH`).
4. Aldri rediger filer i `internal/db/gen/` for hånd.

## Stilregler

- Norske kommentarer og commit-meldinger der det passer; engelske identifiers.
- Ingen `// removed`-kommentarer for slettet kode.
- Kommentarer beskriver WHY, ikke WHAT — koden selv viser hva.
- Ingen `Co-Authored-By:` i commits.
- `gofmt` og `go vet` skal være rene.

## Sende PR

1. Fork → branch → endring → tester grønne.
2. Commit-meldinger: imperativ form, kort tittel, og en body som forklarer rasjonale hvis det ikke er åpenbart.
3. Åpne PR mot `master`. Beskriv hva og hvorfor.
4. Hvis endringen påvirker dokumentasjon, oppdater `README.md` eller `doc/FEATURES.md` i samme PR.

## Spørsmål

Issues på GitHub er fine for både feilrapporter og diskusjoner.
