# scenario-test — kauth

Du tester som en sluttbruker, en tjeneste som integrerer mot kauth, eller en admin. I en IdP er
borderline-scenariene sikkerhetshull — ett sikkerhetsfunn er nok til å stoppe.

## Kode du ikke leser

`internal/`, `cmd/`, `templates/`, `static/` og alle `*.go`-filer. Heller ikke migrasjoner,
sqlc-queries eller eval-databasen.

**Du kan i tillegg lese:** `doc/FEATURES.md` og `/.well-known/openid-configuration` fra den
kjørende eval-serveren.

## Eval-serveren

`dsf.toml [eval] server` (`scripts/run-eval-server.sh [--reset]`) starter en isolert kauth på
`http://127.0.0.1:<port>` (default 8091, `KAUTH_EVAL_PORT`):

- Egen SQLite i `data/eval/`, ferske RSA-nøkler per reset — prod-DB og prod-nøkler røres aldri
- Seedet tjeneste `eval` med callback `http://127.0.0.1:9001/callback` (magic-link aktiv, Google/passord av)
- Seedet bruker `eval-user@example.test`
- `KAUTH_SMTP_MOCK=true`: magic-link-lenker logges til serverens logg (`data/eval/server.log`) i stedet for å sendes
- Ingen Google/Microsoft-credentials — de flytene kan bare testes fram til redirect mot provideren

**Sjekk-URL:** `curl -sf http://127.0.0.1:<port>/.well-known/openid-configuration` skal gi 200 og
`issuer` = `http://127.0.0.1:<port>`.

Aldri `localhost:8083` (prod) eller det offentlige domenet.

## Plassholdere (`.claude/dsf/eval_hooks.py`)

| Plassholder | Gir |
|-------------|-----|
| `{{ACCESS_TOKEN}}` / `{{ACCESS_TOKEN:<epost>}}` | Ekte access-token for `eval-user@example.test` / oppgitt e-post |
| `{{REFRESH_TOKEN}}` / `{{REFRESH_TOKEN:<epost>}}` | Tilhørende refresh-token |

Tokenet skaffes via magic-link mot eval-serveren (lenken leses fra serverloggen) og caches per
e-post i én eval-kjøring. Rate-limiten er 3 per 15 min per e-post — bruk ulike e-poster hvis mange
scenarier trenger hver sin innlogging.

## Typiske scenarier

- **Borderline:** ukjent/avvikende `redirect_uri` (avsluttende `/`, annen host), manipulert `state`,
  utløpt eller gjenbrukt token, deaktivert auth-metode, manglende admin-token, enumeration (ukjent
  e-post skal gi samme svar som kjent)
- **Redirect-mål:** `follow_redirects: false` + `location_matches`/`location_not_matches` — ingenting
  lytter på `127.0.0.1:9001`, så redirect dit må ikke følges
- **Sikkerhetsheadere og cookies:** `header_contains` (`Set-Cookie` med `HttpOnly`, `Cache-Control: no-store` o.l.)
- **Flerstegs-flyter** (magic-link → hent lenke fra loggen → bekreft → callback med token → refresh) med curl når plassholderne ikke dekker dem

Feature-nummer i `scenarios/` starter på `007`.

## Manuell sjekk

- **Ekte Google- og Microsoft-innlogging:** samtykkeskjerm, personlig vs. jobbkonto i Entra ID, avbrutt innlogging
- **E-postlevering:** at magic-link-e-posten kommer fram, ser riktig ut og lenken virker fra mobil-mailklient
- **Cookies bak Cloudflare:** `Secure`/`SameSite` i prod (eval kjører med `KAUTH_INSECURE_COOKIES=true`), innlogging på tvers av tjenester, tilbakeknapp etter login
- **Theming og tekst:** riktig tjenestes farger/logo på login-siden, feilmeldinger på norsk og engelsk
- **Tjenestene selv:** at vinkjeller/pov/andre godtar tokenet etter endringen

Eksempel: «åpne pov sin login på mobil, velg Microsoft med jobbkonto — havner du innlogget i pov, ikke i en annen tjeneste?»
