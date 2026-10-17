# kauth-go — sikkerhetsavklaring og overordnet plan

**Status:** Utkast til godkjenning (2026-10-13)
**Eier:** Lars
**Gjelder:** prod (`master` lokalt, 17d818e — kjører på lilleklo) og `origin/master` (5363c34, 9 commits foran, inkl. authorization_code + PKCE fra kjetil-salo)

Dette dokumentet er paraplyen over de neste featurene. Hver fase under blir én eller flere DSF-features. Hver av dem går gjennom analyse- og plan-gate før kode røres, og analyse og plan holdes lokalt. *Hvorfor*-beslutninger føres i [ARCHITECTURE_DESIGN_NOTES.md](ARCHITECTURE_DESIGN_NOTES.md); *hva som gjenstår* i [BACKLOG.md](BACKLOG.md).

**Grunnlag:**

1. ChatGPT-vurdering «Vurder kauth go» (dokumentbasert, ikke kode) — risikopunkt A–E og en 12-ukers utviklingsplan.
2. Ekstern revisjon (ChatGPT, kodebasert gap-analyse av utvalgte filer) — samme dato.
3. Egen verifisering mot faktisk kode i begge versjoner, med fil:linje-bevis. De kritiske funnene er reprodusert mot en lokal, isolert eval-instans, ikke mot prod.

---

## 1. Sammendrag

Retningen fra begge ChatGPT-rundene holder: kauth-go skal være en passordløs **identity broker** — autentisering delegeres, identitet og autorisasjon eies (se ADN 7). Den eksterne revisjonens rekkefølge — stabil identitet *før* generisk OIDC — er riktig, og den er tatt inn her.

Men verifiseringen fant tre ting ingen av gjennomgangene så, og som endrer prioriteringen: **det finnes en ett-klikks kjede fra en lenke til full admin-overtakelse i prod i dag.**

1. **Open redirect** i `/dispatch` (`/\evil.com` passerer intern-sti-sjekken) sender access-tokenet til en ekstern vert. Reprodusert: `Location: /\evil.example?token=eyJ…`.
2. **`/admin/google-callback`** bytter *ethvert* kauth-signert JWT for en `konge`-bruker til en 8-timers admin-sesjon — ingen sjekk av `token_use` eller `aud`.
3. Kombinert: en lenke til `https://auth…/social-login?redirect_uri=/%5Cevil.com` som en admin klikker på, gir angriperen et access-token, som veksles til admin-sesjon.

I tillegg: admin-skjemaet for tjenester **nuller `require_role`/`enforce_org`** (og per-tjeneste OAuth-credentials) hver gang en tjeneste lagres, og **refresh-grant lar klienten velge tjeneste fritt** uten policy-sjekk. Begge undergraver tilgangskontrollen stille.

Derfor en ny **Fase 0 (akutt herding)** før alt annet. Den er liten (S-tiltak, anslag 3–5 utviklerdager) og kan gå som én DSF-feature.

---

## 2. Risikoregister

Alvorlighet: **K** kritisk · **H** høy · **M** middels · **L** lav. «Prod» = finnes i prod i dag. Str. = S/M/L innsats.

### 2.1 Kritisk

| ID | Funn | Prod | Bevis | Tiltak | Str. | Fase |
|---|---|---|---|---|---|---|
| K1 | **Open redirect lekker access-token.** Intern-sti-sjekken er `HasPrefix("/") && !HasPrefix("//")`; `/\evil.com` slipper gjennom, nettlesere tolker `/\` som `//`. Cookien settes fra query (`/social-login?redirect_uri=`, `google.go:42` og JS i `login.html:207`) | Ja | `dispatch.go:152` (origin), `:86` (prod). Reprodusert lokalt | Eksakt allowlist av interne stier (i dag kun `/admin/google-callback`); avvis `\` og kontrolltegn; krev tom scheme/host etter `url.Parse` | S | 0 |
| K2 | **Token confusion inn i admin.** `HandleGoogleCallback` godtar ethvert gyldig kauth-JWT (access/id/admin, enhver tjeneste) fra `?token=` og utsteder admin-cookie hvis e-posten har `konge` | Ja | `admin/auth.go:276-331`; `Verify` sjekker kun signatur/iss/exp (`token/issuer.go:206-221`) | Erstatt med kortlivet engangs-handoff (`token_use=admin_handoff`, `aud=kauth-admin`, ≤60 s, engangs) eller direkte Google-callback for admin; `Verify` skal ta forventet `token_use`/`aud` | S | 0 |
| K3 | **Tokens i journald.** chi `Logger` logger full `RequestURI`: `/dispatch?token=<AT>&rt=<RT>`, `/admin/google-callback?token=<AT>`, `/magic-login/<token>`. Verifisert i prod-journald (11 + 1 linjer siste uke). Med K2: lokal lesetilgang til logg ⇒ admin | Ja | `cmd/kauth/main.go:101` | Redigerende request-logger (stripp `token`, `rt`, `code`, magic-sti); rydd eksisterende journald etter fiks | S | 0 |

### 2.2 Høy

| ID | Funn | Prod | Bevis | Tiltak | Str. | Fase |
|---|---|---|---|---|---|---|
| H1 | **Admin-lagring nuller tjenestefelt.** Skjemaet mangler `require_role`, `enforce_org`, `google/microsoft_client_id/secret`, `logo_html`, `bg_css`, men `UpdateService` skriver alle → NULL/0. Tilgangskrav slås av stille; per-tjeneste OAuth-klient faller til global | Ja | `admin/services.go:296-332`, `templates/admin/service-edit.html`, `query/services.sql:25-36` | Felt som ikke er i skjemaet beholdes (egen query eller «behold ved tomt»); legg `require_role`/`enforce_org` inn i skjemaet; regresjonstest. **Sjekk prod-DB for tjenester der kravene allerede er nullet** | S | 0 |
| H2 | **Refresh-grant uten tjenestebinding og policy.** `/token` tar `service_id` fra skjemaet, ikke fra refresh-raden, og kjører ikke `checkPolicy`. RT fra åpen tjeneste B ⇒ access-token for A uten A sine krav. Refreshede code-flow-tokens mister `aud` | Ja | `password.go:259-275` (origin), `:115` (prod); `refresh.go:107,170` lagrer `service_id` men returnerer det ikke | Bruk lagret `service_id`, avvis avvik, kjør `checkPolicy`, behold `aud` | S | 0 |
| H3 | **Prod mangler policy-fikser fra origin.** `checkPolicy` kun i Google/MS (ikke magic/passord), og `strings.Contains`-match (`sysadmin` oppfyller `admin`) | Ja | prod `google.go:190-193`; fikset i origin 3801891 | Merge origin → prod (lokale malendringer må håndteres først) | S | 0 |
| H4 | **nOAuth-klassen i Microsoft-flyten.** `/common` + `SkipIssuerCheck`, ingen `tid`-allowlist, ingen `nonce`, ingen `xms_edov`; mapping på `email` → `preferred_username`. En fremmed tenant kan sette `mail` til en eksisterende brukers adresse. Faktisk utnyttbarhet avhenger av app-registreringen «Klarsyn» (`removeUnverifiedEmailClaim`) | Ja | `microsoft.go:108-134,167` | Kort sikt: krev `xms_edov==true` (eller personlig MSA), valgfri `tid`-allowlist per tjeneste, send+verifiser nonce. Varig: identitet på `(tid, oid)` (Fase 2) | S→M | 1 |
| H5 ✔ (kauth-delen i 010, i prod 2026-10-14; klientene i BACKLOG) | **Ingen `aud` på vanlige access-tokens** (kun code-flow har det). Et token for tjeneste B er gyldig mot A for enhver ressursserver som sjekker signatur+iss | Ja | `issuer.go:153-159` | `aud=svc.ID` på alle access-tokens, `jti`; klientene (vinkjeller, pov, klarsyn) begynner å kreve `aud` | M | 1 |
| H6 | **Refresh-race og manglende revokering.** Konsumering, innsetting av barn og family-revoke er tre separate operasjoner; revoke treffer kun `used=0`, så barnet til den som vant racet overlever reuse-deteksjon. Revoked token trigger ikke family-revoke. Logout og deaktivering revokerer ikke | Ja | `refresh.go:125-179`, `query/refresh_tokens.sql:16`, `dispatch.go:228-268` | Én transaksjon; revoke på `family_id` uten `used`-filter; revoke ved logout/deaktivering | S–M | 1 |
| H7 | **CORS `*` med credentials.** `*` i `KAUTH_CORS_ORIGINS` speiler enhver Origin og setter `Allow-Credentials: true` ⇒ ethvert nettsted kan rotere og lese refresh via `fetch(credentials:'include')`. README sier «ikke wildcard». `/token` har heller ingen Origin-sjekk (RT-cookie er `SameSite=None`) | Konfig-avhengig | `auth/middleware.go:47-49` | Avvis `*` ved oppstart; krev Origin i allowlist på cookie-basert `/token` | S | 0 |

### 2.3 Middels

| ID | Funn | Bevis | Tiltak | Str. | Fase |
|---|---|---|---|---|---|
| M1 | **Token-i-URL (legacy-flyten).** Alle login-flyter sender AT+RT i query til `/dispatch`; legacy-callback får `?token=` + `#rt=`. Kan ikke slås av per tjeneste. Ingen `Referrer-Policy` | `dispatch.go:43-53`, `google.go:161`, `magic.go:279` m.fl. | `Referrer-Policy: no-referrer` (Fase 0); internt bytte til engangs-handle i stedet for tokens i URL; per-tjeneste `legacy_token_redirect`; migrer klientene til code+PKCE | M | 0 (header) / 1 |
| M2 (løst i 009) | **Magic link konsumeres på GET** — e-postskannere brenner eller *fullfører* innloggingen (gjelder også `/admin/verify`) | `main.go:135`, `magic.go:212`, `admin/auth.go:172` | Bekreftelsesside på GET, konsumering på POST | M | 1 |
| M3 (løst i 009) | **Magic link: klartekst i DB, svak rate limit, URL-styrt tjeneste.** Token lagres ukryptert; limiter er prosesslokal, ryddes aldri, nøkkel er rå e-post (case-varianter omgår den); admin-magic har ingen limit; `VerifyToken` bruker `?service=` fra URL i stedet for tokenets `ServiceID`; service-ID uescapet i lenken | `magic.go:25-55,135,150,160,181,205`; `admin/auth.go:83-169` | Levert i 009: SHA-256 som for refresh; normalisert e-post; limiter som betinget `INSERT` i DB (også admin); bind til lagret tjeneste; `url.Values` i lenken | S–M | 1 |
| M4 | **Klient-IP kan forfalskes, og kauth lytter på alle interfaces.** `chimiddleware.RealIP` (deprecated, spoofbar) + egen kjede stoler på True-Client-IP/X-Real-IP/XFF/CF-Connecting-IP. Prod lytter på `*:8083` — nåbar fra LAN og docker0 forbi tunnelen. Påvirker audit, ikke authz | `main.go:100,199`; `audit/service.go:70-83` | Fjern RealIP; stol på `CF-Connecting-IP` kun fra loopback, valider med `net.ParseIP`; `KAUTH_HTTP_ADDR` default `127.0.0.1` | S | 0 |
| M5 | **Ingen sikkerhetsheadere.** Ingen CSP, `frame-ancestors`/XFO, `nosniff`, HSTS. Login/admin kan rammes inn; `logo_html` rendres rått uten CSP | grep: 0 treff; `magic.go:86` | Header-middleware | S | 0 |
| M6 (løst i 009) | **Admin-CSRF.** Kun `SameSite=Lax`; søster-apper under samme registrerbare domene er same-site | `admin/*.go` | `Origin`/`Sec-Fetch-Site`-sjekk på alle POST under `/admin` | S | 1 |
| M7 | **Google-flyten:** ingen `email_verified`, ingen nonce til Google, ingen `hd`-støtte, ingen upstream PKCE; `err.Error()` lekkes til bruker (også i MS) | `google.go:61,105-115`; `microsoft.go:116,137` | Krev `email_verified`; nonce + PKCE; valgfri `hd`-allowlist per tjeneste; generiske feilmeldinger | S | 1 |
| M8 | **Signeringsnøkler:** én nøkkel, ingen `kid` i JWT-header (JWKS har hardkodet `kauth-1`), rotasjon = restart og alle tokens ugyldige. `FEATURES.md` påstår feilaktig at rotasjon oppdages automatisk | `issuer.go:32-38,142-149,224-237` | Nøkkelring med `kid`, current/next/previous i JWKS, dokumentert prosedyre | M | 5 |
| M9 (løst i 009) | **Audit er asynkron** (fire-and-forget goroutine; tapes ved feil og SIGTERM). **Admin-JWT kan ikke trekkes tilbake** (middleware slår ikke opp rolle i DB; 8 t) | `audit/service.go:36-58`; `admin/middleware.go:23-35` | Bufret kø med flush ved shutdown (synkront for admin-skriv); rolle-sjekk mot DB i admin-middleware | S–M | 1 |
| M10 | **Passordinnlogging uten rate limit/lockout**, timing-enumerering, kun av/på per tjeneste | `password.go:34-87` | Global kill-switch `KAUTH_PASSWORD_LOGIN_ENABLED` (default av); se beslutning B4 | S | 0 |
| M11 (løst i 009) | **E-post er case-sensitiv** i Google/MS/magic/passord (admin normaliserer) ⇒ duplikatkontoer, omgått limiter | `query/users.sql:5`, `001_init.sql:40` | `lower(trim())` ved inngang + migrering/kollisjonssjekk av eksisterende data | S–M | 2 |
| M12 | **Klienthemmeligheter i klartekst i SQLite.** Vises ikke i UI, audit eller eksport; DB/backup er 0600 og backup bruker `umask 077` (ok) | `001_init.sql:26,28` | Kryptering i hvile med nøkkel fra env, eller flytt til env/fil per tjeneste | M | 5 |

### 2.4 Lav / hygiene

| ID | Funn | Tiltak | Fase |
|---|---|---|---|
| L1 (løst i 009) | Magic-link-e-post sendes selv om lagring av tokenet feiler (sett ved reproduksjon: FK-feil, mail sendt likevel) | Returner før sending ved lagringsfeil | 1 |
| L2 (løst i 009) | Autorisasjonskode brennes før `client_id`/`redirect_uri`/PKCE sjekkes; gjenbruk revokerer ikke tokens fra første innløsning; koder i klartekst | Sjekk først; revoker ved gjenbruk | 1 |
| L3 | `enforce_org=1` med tom `default_org` håndhever ingenting, uten varsel; admin validerer ikke `callback_url` | Admin-validering | 1 |
| L4 | Legacy nivå 1 godtar `redirect_uri` fra *hvilken som helst* tjenestes allowlist, ikke tjenesten man logget inn mot | Begrens til innloggingstjenesten | 0 |
| L5 | Prods discovery annonserer `response_types: code` og `authorization_endpoint: /login`, men prod har ikke code-flyten (løses av merge, H3) | — | 0 |
| L6 | Ingen CI; `gofmt -l` ikke rent (6 filer); `govulncheck` ikke installert; én tag (`v0.1.0`) | GitHub Actions: fmt, vet, test, `-race`, govulncheck | 6 |
| L7 | bcrypt cost 10; `rand.Read`-feil ignoreres i `magic.go:150`; `Invalidate`-feil ignoreres i admin | Opprydding | 1 |

---

## 3. ChatGPTs påstander mot koden

| Påstand | Verdikt | Kommentar |
|---|---|---|
| A — tokens i URL via `/dispatch` | **Bekreftet, verre** | Også RT i query til `/dispatch`, også i code-flyten, og logget til journald. Åpnet K1 og K2 |
| B — refresh-cookie `SameSite=None` | **Bekreftet** | Pluss CORS-`*` med credentials (H7) og ingen Origin-sjekk |
| C — ingen automatisk nøkkelrotasjon | **Bekreftet** | I tillegg ingen `kid` i header og ingen `aud` på access/admin (H5, K2) |
| D — secrets i klartekst | **Bekreftet** / filrettigheter **ok** | Fant H1 i samme kode |
| E — trust boundary mot Cloudflare | **Bekreftet** | Prod lytter på `*:8083`, og RealIP gjør alle headere spoofbare |
| Autorisasjonsfeil «allerede funnet» | **Fikset i origin, ikke i prod** | Refresh-grant (H2) er fortsatt åpen |
| Roller/org som CSV | **Bekreftet** | Eksakt match i origin, substring i prod. CSV beholdes |
| Asynkron audit | **Bekreftet** | `CLAUDE.md` sa «synkront» — rettet |
| «OIDC Code + PKCE finnes» (planens premiss) | **Kun i origin** | Prod må oppgraderes først |

**Ekstern revisjon:** funnene stemmer (e-post som identitet, ingen upstream nonce/PKCE, `SkipIssuerCheck`, refresh uten transaksjon, token-i-URL, `sub=email`). Den overså K1, K2, K3, H1 og H2, og tok derfor ikke med akuttfasen. Den var også uklar på nOAuth-risikoen: problemet er ikke at issuer mangler, men at e-post fra en fremmed tenant brukes som identitet. Begrensningen den selv oppgir (leste bare utvalgte filer) forklarer avviket.

---

## 4. Beslutninger som trengs fra Lars

| # | Spørsmål | Anbefaling |
|---|---|---|
| B1 ✔ | **Kontokobling:** skal samme e-post fra to leverandører automatisk bli samme bruker? | **Nei.** Hver ekstern identitet `(iss, sub)` er sin egen kobling; ny kobling bare etter fersk innlogging med en eksisterende. Overgang: eksisterende e-postbrukere får identiteten koblet *ved første innlogging etter migreringen*, kun fra Google med `email_verified` / MS med `xms_edov` / magic link. Deretter låses koblingen. **Besluttet 2026-10-14:** konfigurerbart per tjeneste, med automatisk kobling på e-post (som i dag) som default |
| B2 ✔ | **`sub`-semantikk:** e-post → stabil ID | Per tjeneste-flagg `sub_format` (`email` default, `id` opt-in). Klientene (vinkjeller, pov, klarsyn, spekto) migreres én og én; `email`-claim beholdes. **Besluttet 2026-10-14:** som anbefalt |
| B3 | **Legacy token-i-URL:** når skal den slutte? | Fase 0 gjør den trygg (K1, L4, Referrer-Policy, loggredigering). Per-tjeneste av-bryter i Fase 1; av som default for nye tjenester; fjernes når alle klienter er på code+PKCE |
| B4 | **Passord:** fjerne helt eller beholde av? | Global kill-switch nå (default av). Fjern koden når ingen tjeneste har `auth_password=1` |
| B5 | **Microsoft-tenants:** alle eller allowlist? | `xms_edov` påkrevd for alle; valgfri `tid`-allowlist per tjeneste |
| B6 | **Merge av origin:** kjetil-salos 9 commits inn i prod | Ja, som første steg i Fase 0. Lokale endringer i `templates/login.html` og `magic-login.html` committes eller stashes først |

---

## 5. Faseplan

Én erfaren utvikler (DSF-pipeline). Estimater i utviklerdager, eksklusive ekstern revisjon.

| Fase | Innhold | Risikoer | Est. | Faktisk (aktiv) | DSF-feature |
|---|---|---|---|---|---|
| **0 — Akutt herding** | Merge origin → prod; K1 intern-sti-allowlist; K2 admin-handoff + `Verify` med forventet `token_use`/`aud`; K3 redigerende logger + rydd journald; H1 skjemabug + sjekk av prod-data; H2 refresh-binding + policy; H7 avvis CORS-`*` + Origin-sjekk på `/token`; M4 bind 127.0.0.1 + fjern RealIP; M5 sikkerhetsheadere inkl. `Referrer-Policy`; M10 passord-kill-switch; L4 | K1–K3, H1–H3, H7, M4, M5, M10, L4, L5 | 3–5 | ca. 2,9 t (13.10) | 007 ✔ |
| **1 — Herd eksisterende flyter** | Utløpstid (`iat`) i signert OIDC-state; full formålsbinding magic-token ↔ tjeneste med eksplisitt `purpose`-kolonne i stedet for `service_id IS NULL` (fra 007-review); Upstream nonce + PKCE (Google/MS); `email_verified`/`xms_edov`/`tid`; refresh i én transaksjon + revoke ved logout/deaktivering; `aud`+`jti` på alle tokens; magic link: bekreftelsesside, hashing, limiter, tjenestebinding; admin-CSRF (og `PostFormValue` i admin-skrivehandlere, fra 007 F4); CORS-allowlist per tjeneste og Origin-sjekk mot RT-ens lagrede tjeneste før rotasjon, samt audit og senere avvisning av cookie-refresh uten Origin (fra 007 F7); audit-kø; admin-middleware mot DB; legacy-av-bryter per tjeneste | H4–H6, M1–M3, M6, M7, M9, L1–L3, L7 | 7–11 | ca. 7,2 t (13.–14.10) | 008–010 ✔ (klientene i BACKLOG) |
| **2 — Stabil identitet** | `user_identities(user_id, provider, issuer, subject)` unik på `(issuer, subject)`; stabil intern ID; e-postnormalisering; migrering med kollisjonsrapport; `sub_format` per tjeneste; eksplisitt kobling/frakobling og recovery (B1, B2). **011 ✔ i prod 2026-10-15:** identitetsmodell, `public_id`, `user_id` på sesjoner, `sub_format`, `auto_link`, admin-godkjent identitet og migrasjonsvakt (stopper i stedet for kollisjonsrapport). **012 ✔ i prod 2026-10-15:** frakobling, e-postendring i admin, e-postepoke på `/dispatch` nivå 0 og admin, engangsbinding av admin-Google og recovery som prosedyre. Eksplisitt kobling og innstramming av overgangsunntaket er utsatt til første tjeneste med `auto_link=0` (Fase 5). **013 ✔ i prod 2026-10-16:** e-postepoke og brukersjekk på `/dispatch` nivå 1–5 (fra eval 012, ikke i opprinnelig plan) | P-funnene, M11 ✔ (011) | 6–9 | ca. 4,9 t (14.–16.10, inkl. 013) | 011 ✔, 012 ✔, 013 ✔ |
| **3 — Felles føderert innlogging** | Felles utstedelse for alle fire metodene (`checkPolicy` og utstedelse ett sted); felles føderert sti for Google og MS uten leverandørregister; ingen parallelle handlere | — | 4–6 | ca. 5,8 t (16.10) | 014 ✔ (i prod 2026-10-16) |
| **4 — Generisk OIDC** | `identity_providers` + `service_identity_providers`; discovery med eksplisitt issuer-allowlist (SSRF-vern); JWKS-cache; lokal OIDC-testleverandør for negativtester | — | 5–8 | ca. 3,7 t (16.10) | 015 ✔ (i prod 2026-10-16) |
| **5 — Policy, admin-UX, nøkler og hemmeligheter** | Provider-admin og tilordning per tjeneste; `allow_magic_link` / `allowed_providers` / `require_federated_login`; nøkkelring med `kid`; secrets kryptert i hvile. **016 ✔ levert (ikke i prod ennå):** leverandørside, tilordning per tjeneste uten omstart og eksplisitt kobling via invitasjon. Gjenstår i 017: policyfelter, nøkkelring og kryptering | M8, M12 | 5–8 | — | 016 ✔, 017 |
| **6 — Test, drift og release** | CI (fmt, vet, test, `-race`, govulncheck); E2E mot testleverandør; restore-test av backup; fuzzing av redirect/callback; oppdatert SECURITY.md/FEATURES.md; ekstern revisjon; `v1.0.0` | L6 | 5–8 | — | 018 |
| | **Totalt** | | **35–55** | **ca. 25 t så langt (Fase 0–4)** | |

#### Estimat mot faktisk (per 2026-10-16)

Faktisk tid er aktiv tid fra lifecycle-telemetrien (`.claude/logs/lifecycle.jsonl`), med pauser over 30 min trukket fra. Den dekker analyse, plan, implementering, review, eval og utrulling. Lars' egen tid til beslutninger, manuell test og `sudo`-steg i prod ligger delvis utenfor. Kalendertid er fra første DSF-commit til «i prod» i git-loggen.

| Feature | Fase | Aktiv | Kalender | Merknad |
|---|---|---|---|---|
| 007 | 0 | 171 min | 13.10 17:20 → 20:14 (3 t) | Lars' eget anslag: ca. 2 t |
| 008 | 1 | 122 min | 13.10 20:17 → 22:57 (2,7 t) | Venting på restart for MS/Google |
| 009 | 1 | 226 min | 13.10 23:03 → 14.10 16:48 (18 t) | Impl. ferdig 02:00, deploy av Lars neste dag |
| 010 | 1 | 86 min | 14.10 17:49 → 20:50 (3 t) | |
| 011 | 2 | 164 min | 14.10 21:41 → 15.10 19:07 (21 t) | Nattpause mellom F2 og F3, beslutning PD8b |
| 012 | 2 | 90 min | 15.10 22:05 → 23:25 (1,3 t) | |
| 013 | 2 (tillegg) | 41 min | 16.10 00:21 → 00:58 (0,6 t) | Fra eval 012 |
| 014 | 3 | 350 min | 16.10 06:32 → 13:04 (6,5 t) | Refaktorering, karakteriseringstester først (F1). Lars-test gjenstår |
| 015 | 4 | 224 min | 16.10 16:49 → 20:27 (3,6 t) | Ingen pauser, én økt. Lars-test (M1–M10) gjenstår |
| **Sum 007–015** | **0–4** | **ca. 25 t** | **13.10 17:20 → 16.10 20:27 (3,1 døgn)** | |

Fase 0–2 var estimert til 16–25 utviklerdager (120–190 t à 7,5 t). De tok ca. 15 timer aktivt, omtrent 2 utviklerdager, altså 8–12 ganger raskere enn estimatet. Forholdet er ganske stabilt per fase: Fase 0 ca. 8–13×, Fase 1 ca. 7–11×, Fase 2 ca. 9–14×. Det som trekker kalendertiden ut, er ventetid på Lars (deploy med `sudo`, ekte innlogging, beslutninger), ikke agentarbeidet.

Fase 3 (014) var estimert til 4–6 dager (30–45 t) og tok ca. 5,8 timer, altså 5–8×. Den er den tregeste fasen så langt. Forbeholdet under slo til: Det fantes ingen ferdig fil:linje-analyse å bygge på, og en ren refaktorering krevde karakteriseringstester før koden kunne flyttes (F1 tok ca. 2 t kalendertid). Testkjøringen ble også lengre (`go test -count=3` på auth tar ca. 5 min). Samlet for Fase 0–3 er estimatet 20–31 dager (150–233 t) mot ca. 21 t faktisk, altså 7–11×.

Fase 4 (015) var estimert til 5–8 dager (37,5–60 t) og tok ca. 3,7 timer, altså 10–16×. Anslaget fra Fase 3 om 5–8× for ny protokollkode slo ikke til. Analysen og planen tok bare ca. 15 minutter, fordi 014 hadde laget den felles fødererte stien som generisk OIDC kunne plugges inn i. Samlet for Fase 0–4 er estimatet 25–39 dager (188–293 t) mot ca. 25 t faktisk, altså 8–12×.

**Kalibrert anslag for resten:** Fase 5–6 er estimert til 10–16 utviklerdager. Fase 5 (policy, admin-UX, nøkkelring og kryptering i hvile) består av avgrensede tillegg på eksisterende struktur, slik Fase 1–2 og 4 gjorde. Med 8–12× gir det **3–8 timer aktivt** for Fase 5. Fase 6 har ca. 3–6 timer agentarbeid (CI, fuzzing, restore-test, dokumentasjon). Ekstern revisjon og E2E mot en ekte leverandør kan ikke presses sammen, og revisjonen føres som egen kalenderpost.

Kodebasen før denne planen (Go-porten, 98 commits 18.06–02.10) er ikke med i tallene.

#### Fordeling på aktivitet (007–015)

Den aktive tiden er fordelt slik. Når en subagent kjører, går tiden til agentens type: `code-review`, `security-review`, `scope-guard` og `migration-guard` regnes som review, `test` og `scenario-test` som testing, og `product-owner` og `explore` som planlegging. Agenter uten type klassifiseres etter beskrivelsen («Impl F3», «Eval 013», «Doc-review»). Kjører flere agenter samtidig, deles tiden likt mellom dem. Uten aktive agenter går tiden til dirigentens gjeldende fase (`analyse`/`plan`, `impl`, `review`, `eval`/`test`). Planlegging omfatter analyse og plan. Testing omfatter holdout-scenarier, eval og test- og scope-agenten.

| Feature | Planlegging | Implementering | Review | Testing | Deploy | Sum |
|---|---|---|---|---|---|---|
| 007 | 22 | 54 | 79 | 17 | 0 | 171 |
| 008 | 16 | 25 | 67 | 12 | 2 | 122 |
| 009 | 23 | 84 | 34 | 64 | 22 | 226 |
| 010 | 9 | 6 | 15 | 57 | 0 | 86 |
| 011 | 23 | 56 | 50 | 35 | 0 | 164 |
| 012 | 17 | 35 | 19 | 19 | 0 | 90 |
| 013 | 3 | 14 | 9 | 15 | 0 | 41 |
| 014 | 14 | 120 | 181 | 35 | 0 | 350 |
| 015 | 13 | 101 | 15 | 89 | 6 | 224 |
| **Sum (min)** | **141** | **494** | **469** | **341** | **30** | **1 475** |
| **Timer** | **2,4** | **8,2** | **7,8** | **5,7** | **0,5** | **24,6** |
| **Andel** | **10 %** | **33 %** | **32 %** | **23 %** | **2 %** | |

**Hva tallene viser:**

- **Kvalitetssikringen tar mer tid enn koden.** Review og testing utgjør 55 % av tiden, mot 33 % for implementering. Selve kodingen går fort (ofte 2–10 min per fase), mens review-runder med security-review på alle auth-differ tar lengst tid.
- **Planleggingen er billig.** 10 % av tiden gikk med til planlegging, men den bærer mye: ROADMAP-funnene med fil:linje-bevis gjorde analysene i Fase 0–2 korte.
- **014 skiller seg ut.** Review tok 52 % av tiden. En ren refaktorering av fire innloggingsflyter ga mange review-runder for å vise at atferden er uendret. Det forklarer det meste av den lavere faktoren for Fase 3.
- **015 har motsatt profil.** Testing tok 40 % av tiden og review bare 7 %. Review-agentene (code, security, scope og migration) gikk parallelt og var ferdige på ca. 2 minutter per fase. Funnene var likevel reelle, blant annet kontoovertakelse via unicode-bretting av e-post (Kelvin-tegnet) i F4. Testagentens mutasjonstesting tok 25–45 minutter i F3 og F4. Implementeringen (45 %) inkluderer en egen rework-runde i F5 og den kjørbare testleverandøren i F6.
- **Deploy ser nesten gratis ut, men er det ikke.** Prod-installasjonen (`sudo`, restart, ekte innlogging) gjør Lars utenfor telemetrien. Det er den som drar ut kalendertiden.

**Forbehold:** Tallene er en tilnærming. Fasemarkørene mangler noen steder. Test- og scope-agenten gjør både testing og scope-sjekk, og den er regnet som testing. Intent-capture av scenarier i analysefasen er også regnet som testing. Dirigentens egen tid mens agenter kjører, blir ført på agentene.

Fase 0 er en forutsetning for alt annet og bør gå før noen klient endres. Fase 1 og 2 kan delvis overlappe; Fase 3 forutsetter Fase 2.

### Utenfor scope (bekreftet)

Egen WebAuthn/passkeys, TOTP/HOTP, passord som fremtidig metode, LDAP/AD, SAML, Postgres/Redis, horisontal skalering. **Apple Sign In** ligger i backlog (årsavgift 99 USD for Apple Developer Program; arkitekturen i Fase 3–4 skal gjøre den til en adapter senere).

### Dokumentasjon som må rettes underveis

- `doc/FEATURES.md`: påstand om automatisk nøkkelrotasjon (:59), `aud` som standard-claim (:51), `token_use`-verdier (:50), «rt sendes ikke til serveren» (:339), family-revoke ved `revoked=1` (:71).
- `README.md:119` / `SECURITY.md`: CORS «ikke wildcard» og IP-tillitsmodell stemmer ikke med koden før Fase 0.

---

## 6. Hvordan planen kjøres

Hver fase startes med `/feature-lifecycle` og får eget løpenummer (fra 007; 001–006 brukt i Quarkus-kauth, se ADN-loggen). Holdout-scenariene for Fase 0 skrives *før* fiksene og skal minst dekke:

- `/\` og `/%5C` i `redirect_uri` gir aldri `Location` utenfor kauth
- et vanlig access-token mot `/admin/google-callback` gir ikke admin-cookie
- refresh med `service_id` ulik tokenets tjeneste avvises
- lagring av en tjeneste i admin beholder `require_role`/`enforce_org`
- `KAUTH_CORS_ORIGINS=*` stopper oppstart

Kauth-endringer er sikkerhetskritiske, så security-review (opus) kjøres for alle diffs under `internal/auth/`, `internal/token/`, `internal/admin/`, `internal/service/` og `cmd/kauth/`.
