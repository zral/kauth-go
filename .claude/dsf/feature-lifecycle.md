# Prosjekttillegg: feature-lifecycle (kauth-go)

Gjelder foran kjernens `feature-lifecycle` der de er uenige.

kauth er sikkerhetskritisk: den utsteder JWT-er som flere tjenester stoler på, og prod kjører på samme maskin (lilleklo) som utviklingen.

## Triage og sikkerhet
- Alltid minst **Medium**: innlogging, token-utstedelse eller -validering, refresh-rotasjon, `redirect_uri`-/callback-validering, state/nonce, cookies, service-resolving (hvilken tjeneste en request tilhører), admin-tilgang, eksponering av personlige data.
- Migration guard sjekker goose-migrasjoner og SQLite-skjema; security review ser særlig etter OIDC-/JWT-feil og tenant-lekkasje.

## Steg 1 — analyse
- Vurder mot `CLAUDE.md` og funksjonsoversikten i `doc/FEATURES.md`.
- Første feature i kauth-go er `007` (001–006 ble brukt i Quarkus-kauth). ADN fortsetter fra ADN 7 (1–6 ligger i Quarkus-loggen).

## Steg 1.5 — refaktor
- Grense: ~800 linjer Go, eller en handler-fil som har vokst til flere ansvar.
- Flytt først innenfor samme pakke (ny fil, uendrede eksporterte signaturer); endre pakkegrenser først når testene er grønne.

## Steg 2.5 — UX
Gjelder login-sidene og andre maler i `templates/`, `static/` og i18n-katalogen. Respekter per-tjeneste-theming (farger, logo, lyst/mørkt tema fra `services`-raden), og ny tekst skal finnes i alle språk. Login-sidene vises for brukere av *alle* tjenester — en endring for én tjeneste skal ikke bryte de andre.

## Steg 3a — selv-verifisering
- [ ] `CGO_ENABLED=0 go build ./...` lykkes og `go vet ./...` er ren
- [ ] Nye ruter er montert i `cmd/kauth/main.go` på riktig sted — admin-ruter inne i gruppen bak `admin.AdminAuthMiddleware`
- [ ] Ny tjeneste-konfig følger kjeden migrasjon → query → `make sqlc` → felt i `service.Service` → bruk i handler; `internal/db/gen/` er ikke redigert for hånd
- [ ] Ingen ignorerte `error`-returverdier, og `r.Context()` sendes videre til DB- og HTTP-kall
- [ ] Muterende admin-operasjoner skriver audit-event via `audit.Service`
- Humanizer gjelder login-sider, magic-link-e-post, feilmeldinger, admin-panel-etiketter og i18n-strenger.

## Steg 3b — agenter
- **Test:** kjør også `go test -race ./...`. Skriv tabelldrevne tester i `_test.go`-filer ved siden av endret kode, med hjelperne i `internal/token/testing.go` og `internal/service/testing.go`. Ingen egen kauth-prosess på prod-porten — en restart logger ut ekte brukere.
- **Dependency guard:** `go.mod` / `go.sum`, også nye indirekte moduler.
- **Migration guard:** nye goose-migrasjoner i `internal/db/migrations/` mot eksisterende skjema, og at `internal/db/gen/` er regenerert med `make sqlc` (ikke håndredigert).
- **Security review — utløses av:**
  - `internal/auth/` (login-flyter, callback, state/nonce, cookies, magic-link, passord, dispatch)
  - `internal/token/` (JWT-utstedelse, JWKS, refresh-rotasjon)
  - `internal/admin/auth.go`, `internal/admin/middleware.go` (admin-innlogging og admin-token)
  - `internal/service/` (service-resolver), `internal/config/` (hemmeligheter, nøkkelstier, cookie-flagg)
  - `cmd/kauth/main.go` (ruting, middleware-rekkefølge, CORS), `internal/db/migrations/`
  - `templates/` (skjema, redirect-mål, escaping), `internal/mail/` (magic-link-lenker)
  - ny avhengighet i `go.mod` med krypto-, JWT- eller nettverksansvar
- Triggeren er bredere enn i en vanlig app fordi kauth *er* sikkerhetsgrensen. **Ikke** security review for lesende admin-listevisninger uten nye skriveoperasjoner, ren i18n-tekst, styling i `static/` eller dokumentasjon.

## Steg 3c — planen ligger i DSF-repoet
DSF-filene (`doc/features/`, `scenarios/`, `.claude/`) er utenfor det offentlige repoet og versjoneres i det private repoet `zral/kauth-go-dsf` med samme arbeidstre (`alias dsf='git --git-dir=$HOME/kauth-go/.dsf.git --work-tree=$HOME/kauth-go'`, se CLAUDE.md). Commit planen med `dsf add -f … && dsf commit -m "dsf(XXX): Fn avkrysset …"` før kode-commiten merket `(XXX Fn)`, ellers stopper `check-phase-ak.sh` den. Aldri `git add -f` på disse i det offentlige repoet. Lenker til plandokumenter i oppsummeringsmailen går til `zral/kauth-go-dsf`.

## Steg 4 — scenariotest og eval
- Integrasjon: `go test -race ./...` + smoke-test mot eval-serveren.
- Kjernespørsmål: *Kan en sluttbruker som logger inn, en tjeneste som integrerer mot kauth, eller en admin bli forvirret, blokkert eller gjøre noe feil — eller ende opp med et token, en sesjon eller en redirect for feil bruker eller feil tjeneste?*
- JA: ny eller endret rute (login, callback, `/token`, `/dispatch`, `/logout`, `/api/me`, `/admin/*`); service-resolving og hvilke auth-metoder som er aktive; flyter som magic-link → klikk → redirect med token, og refresh → rotasjon → gjenbruk avvist; endret kontrakt mot tjenestene (claims, token-TTL, cookie-navn, redirect, discovery/JWKS).
- NEI i tillegg: endring som kun berører cleanup-jobben (`internal/jobs`).
- Gråsone: i18n-tekst eller theming — kjør hvis teksten styrer en beslutning (feilmelding, samtykke).
- Google/Microsoft-flyt: eval-serveren har ingen ekte IdP-credentials, så bare det kauth gjør *før* og *uten* provider-svaret kan testes (redirect-URL, state-parameter, avvisning av ugyldig callback). Resten blir MANUELL SJEKK, og er gyldig grunn for `SKIP_SCENARIOS`.
- Eval-server: `bash scripts/run-eval-server.sh --reset` gir fersk DB, ferske RSA-nøkler og en seedet tjeneste `eval` (callback `http://127.0.0.1:9001/callback`, bruker `eval-user@example.test`). Magic-link-lenker logges til serverens stdout. Helsesjekk: `curl -sf http://127.0.0.1:8091/.well-known/openid-configuration`.

## Steg 5 — commits
Del implementeringen i: migrasjon + regenerert `internal/db/gen/` (ved skjemaendring), deretter Go-kode, maler og statiske filer.

## Steg 6 — deploy
- Bruk **ikke** `make deploy` — den scp-er til en annen vert. Prod er systemd-tjenesten `kauth` på samme maskin bak Cloudflare Tunnel.
- En restart rammer innlogging for **alle** tjenester som bruker kauth.
- Feiler helsesjekken og årsaken ikke er opplagt (typisk migrasjon eller registry-warmup): rull tilbake til forrige binær (`git checkout <forrige commit> && make build && sudo systemctl restart kauth`) og stopp som sikkerhetsventil — nedetid her betyr at ingen tjenester kan logge inn.

## Autonom kjøring
- **Datarisiko (ventil 3):** databasen holder brukere, tjenestekonfigurasjon, refresh-token-familier og audit-logg for *alle* tjenester; tapte brukere eller tjenesterader låser folk ute fra flere apper samtidig.
- **Ventil 2-eksempler:** nøkkelrotasjon, ny redirect_uri hos Google eller i Entra ID, koordinert endring i tjenestene som validerer kauth-tokens.
- **E-post:** `KAUTH_BREVO_API_KEY` og `KAUTH_SMTP_FROM` i `.env` (avsenderen er allerede verifisert, den brukes til magic-link). Ikke bruk eller utvid `internal/mail/` for driftsvarsling.
- **Manuelle handlinger, typisk:** ny `services`-rad eller endrede tjenestefelt i prod via admin-panelet, ny redirect_uri whitelistet hos Google/Entra, Cloudflare Tunnel-rute for ny `auth_host`, oppdatering i en tjeneste som leser nye claims, manuell innlogging med ekte Google/Microsoft-konto.
- Statuslinje og prosesslogg i planen glipper lett i autonom modus — følg 3c-sjekklisten etter hver fase-commit.

## Cross-prosjekt
Typisk mål er en tjeneste som bruker kauth som IdP (vinkjeller, pov/spekto, klarsyn-web) eller plattformdokumentasjonen i `quarkus-simple-auth/doc`. En ny claim i tokenet refererer til ADN-punktet i tjenesten som skal lese den, og omvendt. Endringer i token-format, claims eller JWKS er kontraktsendringer for *alle* tjenester — list hvilke som berøres.
