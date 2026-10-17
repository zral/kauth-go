# Revisjonspakke

Underlag for ekstern sikkerhetsrevisjon av kauth. Det er ikke en revisjonsrapport, og ingen revisjon er bestilt. Bestillingen er eierens beslutning (se [BACKLOG.md](BACKLOG.md)). *Hvorfor* hver beslutning er tatt står i [ARCHITECTURE_DESIGN_NOTES.md](ARCHITECTURE_DESIGN_NOTES.md) (ADN); detaljer om funksjonene i [FEATURES.md](FEATURES.md).

## 1. Formål

Gi en revisor nok til å avgrense arbeidet uten å lese alt: hva kauth er, hvilke aktører og grenser som finnes, hvor hver grense håndheves, hva som allerede er akseptert, og hva som er testet. Rapportering av funn: [SECURITY.md](../SECURITY.md).

## 2. Omfang

### Komponenter

kauth er én statisk, CGO-fri Go-binær med SQLite (modernc.org/sqlite, WAL), bak Cloudflare Tunnel som terminerer TLS. Multi-tenant: én instans betjener flere tjenester datadrevet via `services`-tabellen. Kauth er en identity broker (ADN 7): autentisering delegeres, identitet og autorisasjon eies.

| Pakke | Ansvar |
|---|---|
| `internal/service` | Tjeneste-resolver (redirect_uri og `auth_host` til tjeneste), cache i minnet |
| `internal/token` | RS256-utstedelse, nøkkelring med `kid`, JWKS, discovery, refresh-rotasjon, hashing av engangshemmeligheter |
| `internal/auth` | Google, Microsoft, generisk OIDC, magic link, passord, `/dispatch`, `/token`, state, utlogging |
| `internal/idp` | Generiske OIDC-leverandører: register, discovery, JWKS-cache, utgående klient med SSRF-vern |
| `internal/admin` | Admin-panel, admin-middleware, brukere, tjenester, leverandører, koblingsinvitasjoner |
| `internal/audit` | Audit-kø med én skriver |
| `internal/fetchmeta` | Same-origin-sjekk (Sec-Fetch, Origin) |
| `internal/db` | Skjema (goose), sqlc-spørringer |
| `internal/jobs` | Opprydding av utløpte tokens, koder og audit |
| `cmd/kauth` | Wiring, konfig fra env, router |

### Ruter (se FEATURES «Endepunkter»)

- Anonyme: `/login` (også `authorization_endpoint`), `/oidc-login`, `/callback`, `/ms-oidc-login`, `/ms-callback`, `/idp/{slug}/login|callback`, `/magic-login[/{token}]`, `/link/{token}`, `/do-login` (av som default), `/token`, `/dispatch`, `/logout`, `/api/me`, `/.well-known/jwks.json`, `/.well-known/openid-configuration`, `/static/*`.
- Admin: `/admin/*`. Innlogging åpen (magic link, Google); resten krever `konge`-rolle, slått opp i DB på hver request. Alle ikke-sikre metoder krever samme origin.

### Dataflyter

1. **Føderert innlogging (Google, Microsoft, generisk):** `/login` → leverandør (HMAC-signert state, nonce, PKCE for generisk) → callback → verifisert id_token → identitet `(issuer, subject)` → `checkPolicy` → access- og refresh-token → `/dispatch` → klientens `redirect_uri`.
2. **Magic link:** `POST /magic-login` (rate-limitet, konstant respons) → e-post → `GET` viser bekreftelse → `POST` (samme origin) bruker opp tokenet.
3. **OIDC `authorization_code` + PKCE:** `/login?response_type=code…` → innlogging → engangskode (hash, 60 s) → `/token` med `code_verifier` → access-, id- og refresh-token.
4. **Refresh:** `/token` roterer innen familien; gjenbruk av brukt token revokerer familien.
5. **Admin:** magic link eller Google → admin-token (eget TTL, `aud=kauth-admin`) → middleware slår opp bruker i DB.
6. **Koblingsinvitasjon:** admin lager invitasjon (hash) → bruker åpner `/link/{token}` → `POST` starter kobling hos leverandøren.

### Utenfor omfang

- Cloudflare, Cloudflare Tunnel og vertsmaskinens OS og fysiske sikkerhet.
- Tredjepartsavhengigheter som sådan (meldes oppstrøms). Selve bruken av dem er innenfor.
- Klientene (tjenestene som validerer JWT-er): deres håndheving av `aud` og `token_use` er deres kode (se BACKLOG).
- Sosial manipulering av administratorer.
- Ekstern DoS (basisgrenser finnes; resten er Cloudflare).
- Brevo, Google, Microsoft og andre leverandørers egen sikkerhet.

## 3. Trusselmodell

Forutsetninger: HTTPS-terminering foran, klient-IP fra `CF-Connecting-IP`, admin-brukere (`konge`) opprettet manuelt og betrodd, RSA-privatnøkkel hemmelig, ressursservere validerer JWT mot JWKS (se SECURITY.md).

| Aktør | Kan | Forsøk vi forsvarer mot |
|---|---|---|
| Anonym bruker | Kalle alle åpne ruter | Open redirect via `redirect_uri` og `/dispatch`-mål, enumerering av brukere (magic link, admin-login), brute force og kvote-misbruk på magic link, login-CSRF, gjetting av tokens og koder |
| Innlogget bruker | Holde gyldig access-/refresh-token for én tjeneste | Bruke token mot en annen tjeneste (`aud`, tjenestebinding), gjenbruk av refresh-token, kontoovertakelse via e-post eller kobling, eskalering til admin |
| Admin (`konge`) | Endre brukere, tjenester, koblinger | Admin-sesjon fra vanlig token (`token_use`/`aud`), CSRF mot admin, innføring av ny tillitsrot via databasen, stille tap av tilgangskrav. Betrodd, men all skriving auditeres med `actor=` |
| Ondsinnet tjeneste/klient | Er registrert med egen `redirect_uri` | Hente koder eller tokens for en annen tjeneste, bruke en annen tjenestes allowlist, lekke autorisasjonskode uten PKCE |
| Ondsinnet IdP | Kontrollerer et generisk OIDC-endepunkt | SSRF via discovery, falsk e-post (`trust_email=0` som standard, `email_verified` og domeneliste), tvetydig issuer, stor respons, omdirigering til intern adresse |
| DB-lesetilgang | Leser SQLite-filen eller en backup | Magic-tokens, autorisasjonskoder, refresh-tokens og invitasjoner er hasher. Klienthemmeligheter ligger i env, ikke i DB. Backup og `.env` er likevel sensitive |
| Nettverksangriper | Ser eller endrer trafikk bak Cloudflare, eller når porten | Kauth binder `127.0.0.1`. Cookies er `Secure` (`KAUTH_INSECURE_COOKIES` er bare for lokal HTTP). Uten TLS-terminering gjelder ikke modellen |

## 4. Sikkerhetsgrenser og hvor de håndheves

| ADN | Grense | Håndheves i |
|---|---|---|
| 7 | Kauth eier identitet og autorisasjon; autentisering delegeres | `internal/auth`, `internal/service` |
| 8 | Utviklingsprosess: negative scenarier før kode, security-review på auth-diffs | DSF-pipeline (privat), hooks |
| 9 | Tokenformål og tjenestebinding: `Verify` krever forventet `token_use` og `aud` | `internal/token` (`Verify`), `internal/admin` (middleware), `internal/auth/dispatch.go` |
| 10 | Føderert identitet krever leverandørbekreftet e-post; refresh-familier revokeres som helhet | `internal/auth` (google/microsoft), `internal/token` (refresh) |
| 11 | Engangshemmeligheter er hasher og brukes opp bare ved bevisst POST fra samme origin; admin-tilgang og audit følger DB-en | `internal/token`, `internal/fetchmeta`, `internal/admin` (middleware), `internal/audit` |
| 12 | Access-tokens har `aud` = tjeneste-ID og `jti` | `internal/token` (issuer), `internal/auth` |
| 13 | Identitet er `(issuer, subject)` mot intern bruker med opak `public_id` | `internal/auth` (federated), `internal/db` |
| 14 | Frakobling, e-postendring og admin-binding; tokens med e-post godtas bare etter e-postepoken | `internal/admin` (users), `internal/auth/dispatch.go` |
| 15 | E-postepoke og brukersjekk på `/dispatch` nivå 1–5, fail-open ved DB-feil med audit | `internal/auth/dispatch.go` |
| 16 | Felles utstedelse for alle metoder (`checkPolicy` ett sted), felles føderert sti | `internal/auth` (`loginCompleter`, `federatedLogin`) |
| 17 | Generiske leverandører: to nøkler (tabell og `KAUTH_OIDC_ISSUERS`), utgående klient med SSRF-vern, e-posttillit av som standard | `internal/idp`, `cmd/kauth` |
| 18 | Leverandøradmin uten ny tillitsrot; kobling bevist av brukeren via invitasjon | `internal/admin` (providers), `internal/auth` (link) |
| 19 | Nøkkelring med `kid`; klienthemmeligheter som env-referanse, ikke i DB | `internal/token` (keyring), `internal/config` (nøkler), `internal/service` (env-referanse) |
| 20 | CI uten tilgang til prod; fuzz av redirect/state/dispatch/maskering; restore-test | `.github/workflows/ci.yml`, `scripts/restore-test.sh` |

Redirect_uri-matching er eksakt mot registrert callback (`service.IsAllowedCallback`). State er HMAC-signert med utløpstid og sammenlignes i konstant tid.

## 5. Kjente aksepterte risikoer

Fra ADN og [BACKLOG.md](BACKLOG.md); hver står begrunnet i ADN-en det vises til.

- **Login-CSRF på magic link (ADN 11):** bekreftelsessiden viser ikke e-postadressen. Et offer som trykker en angripers lenke kan logges inn som angriperen.
- **Utlogging via same-site GET (ADN 11):** en kompromittert søster-app kan logge brukeren ut. Ingen tilgangseskalering.
- **Kvote-DoS på magic link (ADN 11):** 3 bestillinger per 15 min blokkerer offerets lenke.
- **Admin kan ta over konto via e-postendring (ADN 14):** admin går god for adressen. Audit med `actor=`, ingen varsel til gammel adresse.
- **Ett sekunds vindu i epokesammenligningen (ADN 14)** og autorisasjonskoder (60 s) brennes ikke ved frakobling.
- **`account_not_linked` røper at kontoen finnes (ADN 13)** for den som har en verifisert leverandørkonto med adressen. Identiteten kobles før `checkPolicy`.
- **`token_endpoint` på annen vert får klienthemmeligheten (ADN 17):** discovery avgjør hvor den sendes (som Google selv gjør).
- **Utgående vakt blokkerer NAT64 m.fl. (ADN 17):** bryter IPv6-only-nett med NAT64.
- **Ferskhets-audit før ruting (ADN 15):** rad med success=1 selv om nivå 5 mangler tjeneste (bare feilkonfigurasjon).
- **Access-tokens kan ikke trekkes tilbake før utløp (ADN 12):** ingen introspection eller `jti`-denylist. Klientene håndhever `aud` selv.
- **Token i URL ved `/dispatch?token=` (ADN 12):** begrenset av ferskhetskrav på nivå 0.
- **Nivå 2 i `/dispatch` bruker `callback_url` rått:** kommaliste ville gitt ugyldig mål; ingen slike i prod (018).
- **`NormalizeEmail` bretter unicode** (Kelvin-tegnet): generisk OIDC krever ren ASCII, de andre flytene ikke ennå.
- **Passordinnlogging uten rate limit (BACKLOG B4):** av i prod.
- **`CF-Connecting-IP` stoles på fra loopback:** lokale prosesser kan sette klient-IP.
- **Magic-link-limiter og enkelte caches er prosess-lokale:** kauth kjører som én instans.
- **`golang.org/x/crypto` v0.53.0:** 4 sårbarheter, ikke nåbare (BACKLOG).
- **Ingen formell penetrasjonstest før denne revisjonen** (SECURITY.md).

## 6. Hva som er testet

- **Enhets- og pakketester** for tokenutstedelse, refresh-rotasjon og gjenbruk, magic-link-limiter, resolver, admin-middleware, SSRF-vakt og leverandørlogikk. Handler-integrasjonstester mot ekte leverandører er bevisst utelatt.
- **CI på push til `master` og på PR (018):** `gofmt`, `go vet`, `go test` (CGO-fri), `go test -race`, `govulncheck` (0 nåbare på go1.26.9). Se [FEATURES.md](FEATURES.md#ci-fuzzing-e2e-og-restore-test).
- **Fuzz (018):** `FuzzIsAllowedCallback`, `FuzzResolveRedirectURI`, `FuzzParseState`, `FuzzStateRoundTrip`, `FuzzDispatchRedirectTarget`, `FuzzMaskPath`. Hvert mål kjørt 2 min lokalt uten funn; 30 s per mål i CI på push til `master` og ved manuell kjøring, ikke på PR.
- **E2E (018):** `go test -tags e2e ./internal/e2e/...` — innlogging mot fake leverandør, kode, token, refresh-rotasjon, gjenbruksdeteksjon. Loopback, ingen nett.
- **Restore-test (018):** nattbackup restaurert til midlertidig mappe, oppstart og radantall bekreftet.
- **Holdout-scenarier og eval (privat DSF-repo):** black-box-scenarier (`.http`) kjøres mot en isolert eval-instans per feature. De ligger ikke i dette repoet og kjøres ikke i offentlig CI.
- **Security-review per fase** av interne agenter på alle diffs i auth, token, admin, service og `cmd/kauth`. Intern; ikke uavhengig.

## 7. Utenfor omfang for revisjonen

Se avsnitt 2. I tillegg: klientenes kode, drift av Pi-en (systemd-herding, backup-cron), Cloudflare-konfigurasjon, og e-postleveringen (Brevo/SMTP) utover hvordan kauth bruker den.

## 8. Kontakt

Eier: Lars Søraas, `lsoraas@gmail.com`. Sårbarhetsrapporter: GitHub Security Advisories eller samme adresse (se [SECURITY.md](../SECURITY.md)).
