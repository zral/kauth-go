# Prosjekttillegg: security-review (kauth-go)

Stack: Go OIDC-identitetsprovider, SQLite (sqlc/goose), server-rendrede maler. Isolasjonsgrensen
er **tjenesten**: kauth betjener flere tjenester fra én instans, og et token eller en sesjon
som krysser tjenestegrensen er den mest sannsynlige alvorlige feilen. Et hull her er et hull i
alle tjenestene som stoler på kauth. Vurder som en penetrasjonstester med OIDC-erfaring, og følg
dataflyten fra request til token.

## Triggerstier

| Sti-mønster | Begrunnelse |
|-------------|-------------|
| `internal/auth/` | Login-flyter (Google, Microsoft, magic-link, passord), callback, state/nonce, cookies, dispatch/logout, `/api/me` |
| `internal/token/` | JWT-utstedelse, JWKS, discovery, refresh-rotasjon og family-revocation |
| `internal/admin/auth.go`, `internal/admin/middleware.go` | Admin-innlogging, admin-token, tilgangsgrensen for admin-panelet |
| `internal/admin/*.go` (skriveoperasjoner) | Opprette/endre brukere og tjenester, eksport, audit |
| `internal/service/` | Service-resolver — tenant-routing |
| `internal/config/` | Hemmeligheter, nøkkelstier, cookie-flagg, CORS |
| `cmd/kauth/main.go` | Ruting, middleware-rekkefølge, CORS, statisk filservering |
| `internal/db/migrations/` | Skjema for brukere, tokens, tjenester, audit |
| `internal/mail/` | Magic-link-lenker og e-postinnhold |
| `templates/` | Skjemaer, redirect-mål, escaping, skjulte felt |
| Ny avhengighet i `go.mod` med krypto-, JWT-, OAuth- eller nettverksansvar | Supply chain |

Ikke trigger for lesende admin-listevisninger, ren i18n-tekst, styling i `static/`, eller
`internal/jobs/` når kun intervall/retensjon endres.

## JWT og nøkler

- [ ] Signering og validering låser `alg` til RS256 — `none`, HS256 og algoritme fra token-headeren avvises
- [ ] `aud` er tjenestens ID; `nbf`/`iat` med liten klokke-toleranse
- [ ] Private nøkkel leses fra `KAUTH_PRIVATE_KEY_PATH` med stramme filrettigheter, havner aldri i logg, respons eller JWKS
- [ ] Claims (`role`, `org`) kommer fra brukerraden/tjenesten — aldri fra request-parametre

## OIDC-flyter

- [ ] `redirect_uri` matches eksakt (skjema, host, port, sti) — ingen case-insensitiv host-sammenligning som åpner for omgåelse
- [ ] `/dispatch`, `/logout` og post-login-mål valideres mot tjenesten
- [ ] `state` er HMAC-signert med `KAUTH_OIDC_STATE_SECRET`, inneholder tjeneste-ID og nonce, verifiseres med `hmac.Equal`, kan ikke gjenbrukes på tvers av tjenester
- [ ] Microsoft `/common` med `SkipIssuerCheck`: signatur, `aud` og `exp` verifiseres fortsatt strengt; tenant/`iss` sjekkes manuelt der det betyr noe
- [ ] Tokens i URL unngås; hvis nødvendig er TTL kort og `Referrer-Policy` satt

## Identitet og kontokobling

- [ ] Kobling på `sub`/`oid`; e-post kun når `email_verified` er sann (nOAuth)
- [ ] `auto_register` kan ikke opprette konto som kolliderer med eksisterende brukers e-post fra en annen provider
- [ ] E-post normaliseres (case, whitespace) før oppslag og lagring
- [ ] Deaktivert bruker eller tjeneste kan ikke logge inn, refreshe eller bruke eksisterende magic-link

## Sesjon, cookies og CSRF

- [ ] `Secure` unntatt eksplisitt `KAUTH_INSECURE_COOKIES` lokalt; tjenestespesifikt cookie-navn/`Path`
- [ ] Muterende admin-endepunkter krever POST og har CSRF-vern
- [ ] Kun JWKS/discovery har åpen CORS; `KAUTH_CORS_ORIGINS` er aldri `*` for endepunkter med credentials

## Refresh, magic-link og passord

- [ ] Refresh-rotasjon atomisk (`UPDATE ... WHERE consumed_at IS NULL`); gjenbruk revokerer hele familien (OAuth BCP §4.13)
- [ ] Magic-token ≥ 128 bit fra `crypto/rand`, bundet til tjenesten det ble bedt om for
- [ ] Rate limit: magic-link 3/15 min per e-post, passord-forsøk
- [ ] Passord hashes med bcrypt/argon2

## Injeksjon og output

- [ ] SQL kun via sqlc — ingen `fmt.Sprintf`, heller ikke for `ORDER BY` eller filter i audit-søk
- [ ] Maler bruker `html/template`; ingen `template.HTML`/`template.JS`/`template.URL` på data fra bruker eller tjeneste-config
- [ ] CSV-eksport (brukere, audit) nøytraliserer formelceller
- [ ] Ingen `os/exec` med brukerdata

## Hemmeligheter og audit

- [ ] Alt via `internal/config`; tokens, magic-lenker, client secrets, `KAUTH_OIDC_STATE_SECRET` og `KAUTH_BREVO_API_KEY` logges aldri — heller ikke i `slog`-attributter med hele requesten (unntak: magic-link i `KAUTH_SMTP_MOCK`, aldri på i prod)
- [ ] Innlogging, feilet innlogging, refresh-gjenbruk og admin-endringer skrives til audit med aktør, tjeneste og IP

## Tenant-isolasjon

- [ ] Alle `/admin/*`-ruter unntatt login/verify/logout/google-* ligger bak `AdminAuthMiddleware`, som validerer signatur, `exp` og admin-rolle
- [ ] Service-resolveren faller ikke tilbake til default-tjenesten når `redirect_uri`/`auth_host` ikke matcher — da avvises requesten
- [ ] `auth_host`/`Host` stoles bare på bak Cloudflare Tunnel; klienten kan ikke velge tjeneste via `X-Forwarded-Host`
- [ ] Token for tjeneste A kan ikke byttes eller refreshes til token for tjeneste B
- [ ] Deaktivert auth-metode avvises i handleren, ikke bare i malen

## Kalibrering

| Grad | Eksempel |
|------|----------|
| K | `alg` ikke låst, redirect_uri-prefiksmatch, konto-overtakelse via uverifisert e-post, admin-rute uten middleware, token på tvers av tjenester, eksponert privatnøkkel |
| A | enumerering, manglende rate limit, refresh-gjenbruk uten family-revokering, token i logg, manglende CSRF på admin-mutasjon |
| M | manglende audit-event, svak cookie-konfig i ikke-prod-sti, CSV-formula injection i admin-eksport |

Sikkerhetsventil i autonom modus: K-funn som krever nøkkelrotasjon, endring hos Google/Entra
eller koordinert endring i tjenestene.
