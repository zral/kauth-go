# Funksjonalitet i kauth

En komplett oversikt over hva kauth gjør og hvordan. README-en gir overordnet motivasjon; dette dokumentet gir detaljen.

## Innholdsfortegnelse

- [Innloggingsmetoder](#innloggingsmetoder)
- [Token-håndtering](#token-håndtering)
- [Multi-tenant arkitektur](#multi-tenant-arkitektur)
- [Admin-panel](#admin-panel)
- [Sikkerhetsmekanismer](#sikkerhetsmekanismer)
- [Cross-host login-flyt](#cross-host-login-flyt)
- [Audit-logg](#audit-logg)
- [Bakgrunnsjobber](#bakgrunnsjobber)
- [Endepunkter](#endepunkter)
- [Datamodell](#datamodell)
- [Drift og kjøremiljø](#drift-og-kjøremiljø)

## Innloggingsmetoder

Fire metoder, alle valgbare per tjeneste via boolean-felter i `services`-tabellen (`auth_google`, `auth_microsoft`, `auth_magic_link`, `auth_password`).

### Google OIDC

Standard OAuth2-flyt med PKCE og state-HMAC. Per-tjeneste OAuth-klient hvis `google_client_id` er satt på service-raden, ellers global klient fra miljøvariabler. Redirect-URI bygges per request fra `Host`-headeren, slik at ulike auth-hostnames kan registreres mot ulike Google-klienter med presise whitelists.

### Microsoft OIDC

Bruker `/common/oauth2/v2.0`-endepunktet for å akseptere både personlige Microsoft-kontoer og bedriftskontoer. ID-token verifiseres med `SkipIssuerCheck` (per-tenant `iss`-claims kreves ikke matche en enkeltverdi). Signaturen valideres mot kanonisk JWKS-URL: `https://login.microsoftonline.com/common/discovery/v2.0/keys`.

### Magic-link på e-post

256-bit kryptografisk tilfeldig token i en lenke, 15 minutters levetid, engangsbruk via atomisk `UPDATE WHERE used = 0`. Anti-enumeration: alle POST-responser ser like ut (status 200, samme melding "sjekk e-post", minimum 200 ms responstid). Rate-limit: 3 forsøk per e-postadresse per 15 minutters glidende vindu.

### Passord

Deaktivert som standard. bcrypt-hashet, lagres i `password_hash`. OIDC-only-brukere får sentinel-verdien `"n/a"` i feltet. Se argumentet for passordfri-default i hoved-README.

## Token-håndtering

### JWT (access token)

RS256-signerte. Claims:
- `sub` — brukerens e-post
- `email`
- `org` — array av tenant-slugs fra `users.orgs` (CSV-felt i DB, splittes ved utstedelse)
- `groups` — array fra `users.roles`
- `name` — valgfri
- `token_use` — `access` eller `admin`
- standard `iss`, `aud`, `iat`, `exp`, `nbf`

TTL settes per tjeneste via `services.access_token_ttl` (ISO 8601-varighet, f.eks. `PT15M`, `PT8H`, `P1D`).

### JWKS + OpenID Discovery

- `GET /.well-known/jwks.json` — eksponerer den offentlige RSA-nøkkelen med `kty=RSA, use=sig, alg=RS256, kid`
- `GET /.well-known/openid-configuration` — standard discovery-dokument med `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `response_types_supported`, etc.
- Resource-servere validerer JWT mot JWKS-URL — kauth-roterte nøkler oppdages automatisk

### Refresh-token-rotasjon

256-bit opake tokens, lagret SHA-256-hashet (`refresh_tokens.token_hash`, 64 hex-char CHECK-constraint). Hver utstedelse skaper en ny familie eller arver eksisterende `family_id`. `POST /token?grant_type=refresh_token` roterer atomisk:

1. Token slås opp via hash, markeres `used = 1`
2. Ny access-JWT + ny refresh-token utstedes med samme `family_id`
3. Eksisterende refresh-cookie overskrives

### Reuse-deteksjon med family-revocation

Hvis et brukt refresh-token forsøkes brukt på nytt, slår kauth opp raden ubetinget via `GetRefreshTokenByHash`. Hvis `used = 1` eller `revoked = 1`, revokeres HELE familien (`RevokeFamilyTokens`) og audit-event `refresh_token_reuse` logges. Klienten får generisk `invalid_grant`, men angriperen og legitime klienten kan ikke begge fortsette — hele kjeden er død. Matcher RFC OAuth-BCP §4.13.

### Per-tjeneste TTL og max-age

- `services.access_token_ttl` — JWT-levetid
- `services.refresh_token_max_age` — hardt tak på familielevetid (NULL = ubegrenset)
- `family_expires_at` settes ved første utstedelse fra `max_age`, arves uendret ved hver rotasjon; klempes på `min(now+30d, family_expires_at)` ved utstedelse

## Multi-tenant arkitektur

### Tjeneste-resolver

`internal/service.Registry` cacher alle aktive tjenester i minnet og resolver request → tjeneste via fire-nivå prioritet:

1. **Eksakt redirect_uri-host == service.domain** — vinner over auth_host. Wire/sub-tjenester deler auth-host med foreldretjenesten men har eget domain.
2. **Host-header == service.auth_host** — for tjenester med dedikert auth-hostname (auth.spekto.live, auth.lilleklo.work)
3. **Eksplisitt service-ID** via `?service=`-query
4. **Suffix-match redirect_uri mot service.domain** — for sub-domener uten egen service-rad

Cache invalideres ved Create/Update i admin-panelet.

### Per-tjeneste branding

- `display_name`, `tagline`, `accent_color`, `theme` (light/dark)
- `logo_html` — rå SVG/HTML, embeddes via `template.HTML` cast
- `bg_image` — sti relativ til `/static/`, rendres som `url('/static/<sti>') center/cover no-repeat fixed`
- `bg_css` — alternativ ren CSS-bakgrunn

### Per-tjeneste OAuth-klienter

`google_client_id`/`google_client_secret`/`microsoft_client_id`/`microsoft_client_secret` overstyrer globale miljøvariabler. Lar ulike tjenester ha separate Google Cloud-prosjekter med presise redirect-URI-whitelists.

### Per-tjeneste auth-flagg

`auth_google`, `auth_microsoft`, `auth_magic_link`, `auth_password`, `auto_register`, `enforce_org`, `is_default`, `active`. Login-templaten viser kun knapper for aktive metoder.

### Default-org og krav-rolle

- `default_org` — CSV-streng som blir `users.orgs` for auto-registrerte brukere
- `default_role` — tilsvarende for `users.roles`
- `require_role` — tjenesten krever at brukeren har denne rollen i `roles` for å logge inn
- `enforce_org` — krever at brukeren har `default_org` i `orgs`

## Admin-panel

Beskyttede ruter under `/admin/*` med separat `admin_token`-cookie (egen JWT med `token_use=admin`). Krever rollen `konge` i `users.roles`.

### Innlogging

- `GET /admin/login` — viking-door bakgrunn, primær Google-knapp + sekundær e-postlenke
- `GET /admin/google-init` — redirecter til `/social-login?redirect_uri=/admin/google-callback` slik at admin-flyten gjenbruker vanlig Google-callback (samme URL som er hvitlistet hos Google)
- `GET /admin/google-callback` — intern handler. Leser JWT fra `?token=` (satt av dispatcher etter Google-callback), verifiserer signaturen, sjekker konge-rolle i databasen, utsteder admin-token og setter cookie
- `POST /admin/login` — magic-link-flyt for admin (anti-enumeration, 200ms floor)
- `GET /admin/verify?token=<X>` — konsumerer magic-token, sjekker konge-rolle

### Brukeradministrasjon

- `GET /admin/users` — pagineret liste med søk på e-post og org-filter
- `GET /admin/users/new` + `POST /admin/users` — opprett bruker (valgfritt bcrypt-passord eller `n/a`)
- `GET /admin/users/{id}/edit` + `POST /admin/users/{id}` — rediger navn, roller, organisasjoner
- `POST /admin/users/{id}/deactivate` — settes `deactivated_at = now()`
- `GET /admin/users/export` — CSV-eksport (formula-injection-beskyttet)

### Audit-logg

- `GET /admin/audit` — paginert visning, filter på e-post og service-ID
- `GET /admin/audit/export` — CSV-eksport

### Tjenestehåndtering

- `GET /admin/services` — liste alle tjenester
- `GET /admin/services/new` + `POST /admin/services` — opprett ny
- `GET /admin/services/{id}/edit` + `POST /admin/services/{id}` — full redigering inkludert fil-upload for bakgrunnsbilde
- Cache-invalidering trigger automatisk etter mutasjon

### Bakgrunnsbilde-upload

Multipart-form med fil-validering: kun jpg/jpeg/webp/png, ≤1 MB. Filnavn genereres som `<service-id>-bg-<8 hex>.<ext>` for å unngå kollisjoner. Lagres i `static/`-katalogen og `bg_image`-feltet settes automatisk.

## Sikkerhetsmekanismer

### HMAC-signert OIDC-state

State-cookien som sendes til OIDC-providere inneholder serviceID + 128-bit nonce, signert med HMAC-SHA256. Sammenligningen ved callback bruker `hmac.Equal` (konstant-tid mot timing-angrep).

### Cookie-hygiene

Alle cookies har `HttpOnly: true` og `Secure: true` i prod (over Cloudflare HTTPS). `KAUTH_INSECURE_COOKIES=true` slår av Secure for lokal HTTP-utvikling. SameSite settes per kontekst:
- `auth_token` (per-service navn): `Lax`
- `refresh_token`: `None` (cross-origin SPA-støtte for `POST /token`)
- `admin_token`: `Lax`, path `/admin`
- `oidc_state` / `redirect_uri`: `Lax`

### Anti-enumeration

`POST /magic-login` og `POST /admin/login` returnerer alltid samme respons uavhengig av om e-postadressen finnes — samme melding, samme status (200), og minst 200 ms responstid (defer-sleep om saksflyten gikk for raskt).

### Rate-limiting

Magic-link: 3 forsøk per e-post per 15-minutters glidende vindu. Lagret in-memory per kauth-prosess.

### Audit-isolering

Audit-logging skjer i en goroutine separat fra auth-flyten. Hvis databasen er treig eller utilgjengelig, fortsetter auth uten å blokkere. Lar oss aldri miste en innlogging fordi audit-log-en haltet.

### IP-tracking via Cloudflare

`ClientIPMiddleware` ekstraherer klient-IP fra `CF-Connecting-IP` → `X-Forwarded-For` (første element) → `RemoteAddr`. Verdien legges i request-context og logges i audit-events.

### CSV-injection-beskyttelse

`csvEsc` legger til `'`-prefiks på felter som starter med `=`, `+`, `-`, `@`, `\t` eller `\r` for å nøytralisere formel-evaluering i Excel/Sheets. CSV-quoting håndteres av `encoding/csv` selv.

### Constant-time admin-rolle-sjekk

Admin-middleware verifiserer JWT, sjekker `token_use == "admin"` og deretter `groups`-claim for `konge` — alle kontroller før requesten slipper inn.

## Cross-host login-flyt

Brukeren går til en app (f.eks. `analyse.klarsyn.net`), blir redirected til auth-domain (`auth.klarsyn.net`). Etter vellykket login MÅ JWT komme tilbake til app-domenet — cookies funker ikke cross-host. Flyt:

1. App: `→ https://auth.<svc>/login?redirect_uri=<app-callback>`
2. Login-siden setter `redirect_uri`-cookie via JS og redirecter til valgt auth-provider
3. Provider-callback (`/callback`, `/ms-callback`, `/magic-login/{token}`, eller `POST /do-login`) utsteder JWT + refresh-token
4. Callback redirecter til `GET /dispatch?token=<jwt>&rt=<refresh>` (URL-param, ikke cookie)
5. Dispatcher leser tokenet, verifiserer signaturen, sjekker `redirect_uri`-cookien mot allowlist
6. Redirect til app-callback med `?token=<jwt>#rt=<refresh>` — JWT som query-param, refresh-token som URL-fragment (fragmentet sendes ikke til serveren, og ikke til Referer)
7. App leser `?token=` fra URL, validerer mot JWKS

Refresh-token-cookien settes parallelt på auth-domenet med `SameSite=None` slik at `POST /token` fungerer cross-origin.

### Intern dispatch (admin Google-flyten)

Når `redirect_uri`-cookien starter med `/` (intern path, ikke en ekstern URL), dispatcheren hopper over allowlist-sjekken og redirecter direkte til intern handler med `?token=<jwt>`. Brukt av admin Google-flyten: `/admin/google-init` → `/social-login?redirect_uri=/admin/google-callback` → vanlig Google OAuth → `/callback` → `/dispatch` → `/admin/google-callback?token=<jwt>` → admin-token-cookie og redirect til `/admin/users`. Protokoll-relativ path (`//evil.com`) avvises som potensiell open-redirect.

## Audit-logg

Lagret i `audit_events`-tabellen med felter:
- `event_type` — `login_success`, `login_failed`, `magic_link_login`, `google_oidc_login`, `microsoft_oidc_login`, `admin_login`, `admin_logout`, `admin_google_login`, `refresh_token_issued`, `refresh_token_rotated`, `refresh_token_reuse`, `service_created`, `service_edited`, ...
- `auth_method` — `google`, `microsoft`, `magic_link`, `password`, `refresh`
- `email`, `service_id`, `ip_address`, `user_agent`
- `success` — bool, alltid eksplisitt satt av applikasjonen
- `details` — fritekst, brukes for grunn på feilet login
- `created_at` — ISO 8601 UTC

90 dagers retensjon (cleanup-jobb sletter eldre). Eksporteres via admin GUI som CSV.

## Bakgrunnsjobber

Tre goroutiner, alle med 1 times tick, kjører umiddelbart ved oppstart:

- **`cleanMagicTokens`** — sletter brukte magic-tokens som er utløpt, og ubrukte som er eldre enn 24 timer
- **`cleanRefreshTokens`** — sletter refresh-tokens der `expires_at` er passert OG `family_expires_at` enten er null eller passert
- **`cleanAuditEvents`** — sletter audit-events eldre enn 90 dager

Alle stopper rent på `ctx.Done()` ved SIGTERM/SIGINT.

## Endepunkter

### Offentlige

| Metode | Sti | Beskrivelse |
|---|---|---|
| GET | `/login` | Login-side, valgfri `?service=<id>` og `?redirect_uri=<url>` |
| GET | `/login.html`, `/login-pov.html` | Legacy 301 → `/login` |
| GET | `/oidc-login`, `/social-login` | Initier Google OAuth |
| GET | `/callback` | Google OAuth callback |
| GET | `/ms-oidc-login`, `/ms-social-login` | Initier Microsoft OAuth |
| GET | `/ms-callback` | Microsoft OAuth callback |
| GET | `/magic-login` | Magic-link-skjema |
| POST | `/magic-login` | Send magic-link |
| GET | `/magic-login/{token}` | Konsumer magic-token |
| POST | `/do-login` | Passord-login (hvis aktivert) |
| POST | `/token` | OAuth2 refresh-grant — CORS-aktivert |
| GET | `/dispatch` | Post-login dispatcher |
| GET | `/logout` | Slett cookies, redirect |
| GET | `/api/me` | JWT-introspection (returnerer claims som JSON) |
| GET | `/.well-known/jwks.json` | JWKS — CORS-aktivert |
| GET | `/.well-known/openid-configuration` | Discovery — CORS-aktivert |
| GET | `/static/*` | Statiske filer |

### Admin

| Metode | Sti | Beskyttelse |
|---|---|---|
| GET | `/admin/login` | Åpen |
| POST | `/admin/login` | Åpen — anti-enumeration |
| GET | `/admin/verify` | Åpen — krever magic-token |
| GET | `/admin/logout` | Åpen |
| GET | `/admin/google-init` | Åpen — redirect til `/social-login?redirect_uri=/admin/google-callback` |
| GET | `/admin/google-callback` | Åpen — leser JWT fra `?token=`, sjekker konge-rolle og setter admin-cookie |
| GET | `/admin/users[/new/{id}/edit/export]` | konge-rolle |
| POST | `/admin/users[/{id}[/deactivate]]` | konge-rolle |
| GET | `/admin/audit[/export]` | konge-rolle |
| GET, POST | `/admin/services[/new/{id}/edit]` | konge-rolle |

## Datamodell

Fem SQLite-tabeller med WAL og foreign keys på:

### `services`

Tjeneste-konfigurasjon. 30+ kolonner inkludert id, display_name, domain, auth_host, callback_url, branding (theme, accent_color, logo_html, bg_image, bg_css), auth-flagg (auth_google/microsoft/magic_link/password), OAuth-creds (per-service), TTL-er, default_role/org, is_default, active, updated_at.

### `users`

Brukerkontoer: id, email, password_hash, name, roles (CSV), orgs (CSV), created_at, last_login, deactivated_at.

### `magic_tokens`

Engangs-innloggingstokens: id, token, email, service_id, redirect_uri, created_at, expires_at, used.

### `refresh_tokens`

Opake refresh-tokens med family-tracking: id, token_hash (sha256 hex, CHECK length=64), email, service_id, family_id, parent_id, created_at, expires_at, family_expires_at, used, revoked, revoked_reason, ip_address, user_agent.

### `audit_events`

Hendelseslogg: id, event_type, auth_method, email, service_id, ip_address, user_agent, success, details, created_at.

## Drift og kjøremiljø

- **Single static binær** — ingen CGO, ingen runtime-avhengigheter (modernc.org/sqlite)
- **Cross-compile** — `make build-arm64` for ARM64-linux
- **Graceful shutdown** — `signal.NotifyContext` + `srv.Shutdown(15s)`, cleanup-goroutiner stopper rent på `ctx.Done()`
- **Minne** — `GOMEMLIMIT=96MiB` + cgroup `MemoryHigh=112M` / `MemoryMax=128M` via systemd
- **Strukturerte logger** — `log/slog`, JSON-format, til journald via systemd
- **WAL-modus** — SQLite med `journal_mode=WAL` og `foreign_keys=ON` ved oppstart
- **Daglig backup** — `scripts/backup-kauth-go.sh` via cron 03:00, `sqlite3 .backup` for atomisk konsistent kopi (trygt mens kauth kjører), 30 dagers retensjon
- **Cloudflare Tunnel** — TLS-terminering og DDoS-beskyttelse, klient-IP via `CF-Connecting-IP`
- **systemd-tjeneste** — kjører som `lars`, `ProtectSystem=strict`, `NoNewPrivileges`, `Restart=on-failure`
