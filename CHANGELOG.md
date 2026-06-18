# Changelog

Alle merkbare endringer i prosjektet dokumenteres her. Format inspirert av [Keep a Changelog](https://keepachangelog.com/), kategorier: Added, Changed, Fixed, Security, Deprecated, Removed.

## [Unreleased]

### Added

- `SECURITY.md` med rapporteringsguide og threat model.
- `CHANGELOG.md`.
- `CONTRIBUTING.md` med lokal utvikling, struktur og PR-prosess.
- `.env.example` med alle konfig-variabler.

### Changed

- Admin Google-login bruker nå samme `/callback`-URL som vanlig brukerflyt, via intern `redirect_uri`-cookie til `/admin/google-callback`. Matcher Java-originalens mønster og krever ikke separat redirect-URI hvitlistet hos Google.
- `doc/FEATURES.md` oppdatert med admin Google-flyt-detaljer og intern-dispatch-seksjon.

## [0.1.0] — 2026-06-18

Første portering av kauth fra Quarkus til Go er ferdig og kjører i prod.

### Added

#### Auth-flyter

- Google OIDC med HMAC-signert state og per-host redirect_uri
- Microsoft OIDC mot `/common`-endepunktet, kanonisk JWKS-URL
- Magic-link på e-post med 15-minutters TTL, atomisk konsumering, rate-limiting og anti-enumeration
- Passord-login (deaktivert som default; bcrypt-hashing når aktivert)
- Cross-host login-flyt: JWT som URL-query, refresh-token som URL-fragment til app-callback

#### Token-håndtering

- RS256-signerte JWT-er
- JWKS- og OpenID Discovery-endepunkter
- Refresh-token-rotasjon med opake tokens (SHA-256 hashet)
- Family-revocation ved gjenbruksdeteksjon (RFC OAuth-BCP §4.13) via `GetRefreshTokenByHash`
- Per-tjeneste TTL og refresh-token-max-age

#### Multi-tenant

- Datadrevet service-config-tabell
- Tjeneste-resolver med fire-nivå prioritet (eksakt redirect_uri-match, auth_host, service-ID, suffix-match)
- Per-tjeneste branding (theme, accent_color, logo_html, bg_image, bg_css)
- Per-tjeneste OIDC client_id/secret-overstyring
- Cache-invalidering ved service-mutasjon
- Host-match i dispatcher for auth_host → service-routing

#### Admin-panel

- Innlogging via magic-link og Google OIDC
- Konge-rolle som autorisasjonsbase
- Bruker-CRUD med paginering, søk og org-filter
- Audit-logg med eksport som CSV
- Tjeneste-CRUD med cache-invalidering
- Bakgrunnsbilde-upload med MIME-validering og 1 MB-grense

#### Sikkerhet

- HMAC-state for OIDC med konstant-tids sammenligning
- HttpOnly + Secure cookies (overstyrbart med `KAUTH_INSECURE_COOKIES` for lokal HTTP)
- Anti-enumeration med 200ms minimum-respons-tid og identiske svar
- Rate-limiting på magic-link (3 per 15 min per e-post)
- Audit-isolering i goroutine — audit-feil blokkerer aldri auth-flyt
- IP-tracking via Cloudflare-header (`CF-Connecting-IP`)
- CSV-injection-prefiks-håndtering (`'`-prefiks på `=`, `+`, `-`, `@`, `\t`, `\r`)
- Open-redirect-beskyttelse i dispatch (avviser `//evil.com`-mønstre)

#### Drift

- Statisk Go-binær (~14 MB) uten CGO
- Cross-compile til ARM64-linux via `make build-arm64`
- Graceful shutdown via `signal.NotifyContext`
- Cleanup-jobber for magic-tokens, refresh-tokens og audit-events (90 dagers retensjon)
- WAL-modus SQLite med `foreign_keys = ON`
- Daglig backup via `scripts/backup-kauth-go.sh` (cron 03:00, 30 dagers retensjon)
- systemd-unit med `GOMEMLIMIT` og cgroup-minnegrenser
- Strukturerte logger via `log/slog`

#### Verktøy

- `scripts/migrate-h2/` — engangsverktøy for H2 → SQLite-migrering fra Java-versjonen
- `scripts/backup-kauth-go.sh` — daglig SQLite-backup

#### Dokumentasjon

- README.md med onboarding, OIDC-oppsett og det passordløse valget
- `doc/FEATURES.md` med detaljert funksjonsoversikt
- MIT-lisens

### Migrasjon fra Java-versjonen

Data fra `quarkus-simple-auth` (H2-database) ble migrert via `scripts/migrate-h2/`. Reverse-migrering (SQLite → H2) for kald fallback ligger i `quarkus-simple-auth/scripts/migrate-to-h2/`. Cloudflare Tunnel ble pekt om fra Java-container på port 8082 til kauth-go på port 8083.

[Unreleased]: https://github.com/zral/kauth-go/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/zral/kauth-go/releases/tag/v0.1.0
