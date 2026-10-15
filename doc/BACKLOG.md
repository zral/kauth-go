# Backlog

**Hva dette er:** én liste over arbeid som faktisk gjenstår, med eier og hvorfor det venter. Oppdateres som del av feature-lifecycle.

**Hva dette ikke er:** en beslutningslogg. *Hvorfor* noe er bestemt står i [ARCHITECTURE_DESIGN_NOTES.md](ARCHITECTURE_DESIGN_NOTES.md). Faser, risikoregister og estimater står i [ROADMAP.md](ROADMAP.md). Ved motstrid er ADN-en fasit.

Sist gjennomgått: 2026-10-15

---

## Neste (rekkefølge)

| # | Sak | Hvorfor | Ref |
|---|-----|---------|-----|
| 1 | **007 Akutt sikkerhetsherding** (Fase 0) | Ett-klikks kjede fra lenke til admin-overtakelse i prod (K1+K2). Tilgangskrav nulles stille ved admin-lagring (H1) | ROADMAP §2.1–2.2 |
| 2 | Beslutning B1–B6 | Blokkerer analyse for Fase 1–2 | ROADMAP §4 |
| 3 | ~~010 Herd eksisterende flyter, del 3 (Fase 1): `aud`/`jti` på alle tokens (H5)~~ | ✔ I prod 2026-10-14. Klientene krever `aud` i egne leveranser (se Senere) | ADN 12 |
| 4 | 011 Stabil identitet (Fase 2, del 1): ✔ I prod 2026-10-15 (tag `011`). **Neste:** 012 (frakobling og e-postendring i admin, e-postepoke på `/dispatch` nivå 0 og admin, recovery som prosedyre) | Må være på plass før flere leverandører kommer til | ADN 13, ADN 14 |

## Senere

| Sak | Hvorfor den venter | Ref |
|-----|--------------------|-----|
| wspekto: send `service` på Google/MS-knappene i login.html, deretter håndhev L4 | L4 logges fra 007. Å håndheve før dette er rettet ville brukket Google-login for wspekto | ROADMAP L4, ADN 9 |
| CORS for `klarsyn.net` og `klarsyn.lilleklo.work` | Refresh fra disse vertene feiler i dag. Først avklares det om de skal refreshe fra nettleser | ROADMAP H7 |
| Nekt `KAUTH_SMTP_MOCK=true` ved https-issuer | Mock-mailen skriver gyldige magic-lenker til journald. Ikke satt i prod i dag, men ingenting hindrer det (007 F1, security review U1) | ROADMAP I3 |
| Generiske feilmeldinger til klient | `err.Error()` fra JWT-validering og SQLite sendes til klienten, bl.a. i `microsoft.go` og admin-middleware (007 F1, security review U2) | ROADMAP M7 |
| Fjern avsluttende `/` fra `KAUTH_BASE_URL` i `config.Load` | Gir `//magic-login/` i lenkene ved feilkonfig. Prod er korrekt i dag (007 F1, code review A1) | — |
| Valider `callback_url` ved lagring i admin, og bruk første trimmede oppføring på nivå 2–5 | Feltet lagres uvalidert. En CSV-verdi eller relativ URL gir feil redirect på nivå 2–5, og nivå 1 godtar alt admin registrerer (007 F3, security M2 og code review S3) | ROADMAP L3 |
| Plant `redirect_uri`-cookien bare når den er gyldig for tjenesten (google.go, login.html) | Ufarlig etter F3, men det er selve inngangen til redirect på tvers av tjenester (007 F3, security S1) | ROADMAP L4 |
| Valider tjeneste-ID (slug `^[a-z0-9-]+$`) ved opprettelse i admin | `HandleCreate` bruker ID-en i filsti for bakgrunnsbilde, så `../` skriver utenfor `static/` (bak admin-innlogging) (007 F4, security S3) | — |
| Rotering av per-tjeneste OAuth-credentials | Kan ikke gjøres i admin-UI etter 007 F4 (bevisst). Må gjøres direkte i DB, eller i et eget skjema med secret-felt som bare kan skrives | ROADMAP M12 |
| Rate limit og dummy-bcrypt på `/do-login`, eller fjern passordkoden helt (B4) | Når `KAUTH_PASSWORD_LOGIN_ENABLED=true` gjelder fortsatt: ingen rate limit og et timing-orakel for brukeroppregning. Bryteren står av i prod (007 F6, security M1) | ROADMAP M10, B4 |
| Strip standardport og konverter IDN i `KAUTH_CORS_ORIGINS` | `https://a.example:443` og Unicode-verter godtas, men matcher aldri det nettleseren sender (007 F7, code review S-b) | ROADMAP H7 |
| Begrens audit-rader fra gjentatte `/dispatch`-kall | En autentisert bruker kan generere mange audit-rader via gjentatte `/dispatch`-kall (`redirect_service_mismatch`). Vurder rate limit eller dedup. Gjelder også `dispatch_aud_mismatch` og `dispatch_token_stale` (007 F9, 010 F3 M2) | — |
| Sterkere kilde-autentisering for `CF-Connecting-IP` | Loopback-tillit betyr at lokale prosesser på boksen kan sette klient-IP. Vurder unix-socket eller delt hemmelighet fra cloudflared (007 F10) | — |
| vinkjeller: del refresh på tvers av faner (Web Locks/single-flight, som klarsyn) | Samtidige refresh fra flere faner gir reuse, og etter 008 logger det ut begge parter (008 F2, ADN 10 pkt 5) | ROADMAP H6 |
| Overvåk W1-utløseren: reuse med `gap_s ≤ 2`, samme IP og UA | Slår den til, revurder idempotensvindu for samtidig refresh. Ellers ingen tiltak (008, ADN 10 pkt 5) | ROADMAP H6 |
| Audit-volum fra gjentatte presentasjoner av revokerte tokens | Hver presentasjon logger `refresh_token_revoked_presented`. Vurder rate limit eller dedup (008 F3) | — |
| Legacy token-i-URL av-bryter per tjeneste (B3) | Står i ROADMAP Fase 1, men ble ikke tatt i 008–010. Av som default for nye tjenester. Fjernes når alle klienter er på code+PKCE | ROADMAP M1, B3 |
| CORS-allowlist per tjeneste, avvis cookie-refresh uten `Origin` | Står i ROADMAP Fase 1. I dag er allowlisten global (`KAUTH_CORS_ORIGINS`). Origin-sjekken før rotasjon finnes, men mot den globale listen | ROADMAP H7 |
| Fase 3–6 | Forutsetter Fase 2 | ROADMAP §5 |
| Apple Sign In | Løpende kostnad. Kommer som adapter etter Fase 4 ved dokumentert behov | ADN 7 |
| GitHub/LinkedIn m.fl. | Kan i stor grad dekkes av generisk OIDC (Fase 4) | ROADMAP §5 |
| Deaktivert bruker på tjeneste med auto-register gir `login_failed` i stedet for `access_denied` | Uventet feilkode, ufarlig (008 F10 S2) | — |
| Audit for «ingen konto», policybrudd og DB-feil i vanlig gren av Google-flyten | Bare avvisning på `email_verified` auditeres i dag (008 F10 S3) | — |
| OIDC-klient i authorization_code-flyten mister `oidc_authz` ved ugyldig state og får ingen spec-feil-redirect | Klienten ender på `/login` i stedet for `redirect_uri?error=` (008 F9 S3) | — |
| Limit per IP på `POST /magic-login` | Også e-postflom via aliaser (`x+1@`) mot én innboks. Kvoten per e-post stopper dem ikke. Krever en IP-modell (ADN 9 pkt 7, 009 F3) | ADN 11 |
| vinkjeller og univers-authgate kaller ikke kauth `/logout` | Refresh-familien revokeres ikke ved utlogging der. spekto bør bekreftes (009 P-betingelser) | ROADMAP H6 |
| Audit i samme transaksjon som admin-endringen | I dag logges `LogSync` etter at endringen er lagret. Feiler audit, står endringen og listen viser advarsel. Gjøres ved behov (009 F7) | ADN 11 |
| PB2 fail-open som beredskap | Magic-bekreftelse og admin-POST avvises når både `Sec-Fetch-Site` og gyldig `Origin` mangler. Viser P7 (iPhone-Mail, Gmail-appen) eller drift problemer, kan sjekken snus til fail-open uten DB-endring (009 PB2) | ADN 11 |
| vinkjeller: krev `aud` (streng eller array) og `token_use` | Kauth setter `aud=vinkjeller` fra 010. Tidligst én access-TTL og én refresh-syklus etter deploy av 010 | ADN 12 |
| pov (spekto, spekto-dev): krev `aud` (streng eller array) og `token_use` | Som over. Godta begge tjeneste-ID-ene | ADN 12 |
| klarsyn-web: krev `aud` (streng eller array) og `token_use` | Som over. analyse.klarsyn.net logger inn som `klarsyn`, så `aud=klarsyn` dekker begge | ADN 12 |
| univers/authgate: krev `aud` (streng eller array) og `token_use` | Som over, `aud=univers` | ADN 12 |
| wspekto: krev `aud` (streng eller array) og `token_use` | Repoet avklares først. Som over, `aud=wspekto` | ADN 12 |
| Engangs-handoff i stedet for access-token i `/dispatch?token=` | Tokenet ligger i URL-en (historikk, Referer, logger). Ferskhetskravet på nivå 0 begrenser skaden, men fjerner den ikke (010) | ADN 12 |
| `auth_time`-claim som ferskhetsgrunnlag på `/dispatch` nivå 0 | Settes bare ved interaktiv innlogging og arves ved refresh. Uten den kan et lekket refresh-token gå via refresh til nivå 0 og lage en ny familie med ny absolutt levetid (010 F3, security M1) | ADN 12 |
| Introspection eller `jti`-denylist | Access-tokens kan ikke trekkes tilbake hos klientene før de utløper. `jti` finnes fra 010 (ADN 12 pkt 4) | ADN 12 |
| Kortere access-TTL for univers (12 t) og refresh i authgate | Største eksponering for lekkede access-tokens, uavhengig av `aud` (ADN 12) | ROADMAP H5 |
| Håndhev `aud` på `/dispatch` nivå 1–5 | Når `dispatch_aud_mismatch` er ren i auditen. Nå bare logget (010 F3) | ADN 12 |
| `fetchmeta.SameOrigin` på `POST /do-login` og `POST /magic-login` | Login-CSRF: en fremmed side kan logge offeret inn på en konto angriperen kontrollerer. Fantes fra før, men gjelder nå alle auth-hoster. Passord er av i prod (010 F2, security M1) | ADN 11 |
| Avvis eller logg på `/token` når familiens `auth_host` ≠ `r.Host` | Passord på fremmed host med undertjeneste setter `refresh_token`-cookie på den hosten (010 F2, security M2) | — |
| `DoLogin` 403/401 avslører om passord er på per tjeneste | Tjeneste-ID-er er ikke hemmelige, så lav alvorlighet. Tas sammen med B4 (010 F2, security S1) | ROADMAP B4 |
| Den ubrukte `analyse`-raden i `services` | analyse.klarsyn.net logger inn som `klarsyn`, så raden brukes ikke. Fjern eller dokumenter (010) | ADN 12 |
| Kvote-DoS på magic link | 3 bestillinger per 15 min blokkerer offerets magic link. Akseptert risiko, som før 009 (009 F3 S3s) | ADN 11 |
| vinkjeller: godta `sub` som UUID, match eksisterende brukere på `email` første gang | Kontrakten for `sub_format=id`. Når klienten er klar, bytter kauth `sub_format` for tjenesten. Ingenting skjer før | ADN 13 |
| pov (spekto, spekto-dev): godta `sub` som UUID, match på `email` første gang | Som over. Begge tjeneste-ID-ene | ADN 13 |
| klarsyn-web: godta `sub` som UUID, match på `email` første gang | Som over. analyse.klarsyn.net logger inn som `klarsyn` | ADN 13 |
| univers/authgate: godta `sub` som UUID, match på `email` første gang | Som over | ADN 13 |
| wspekto: godta `sub` som UUID, match på `email` første gang | Repoet avklares først. Som over | ADN 13 |
| Eksplisitt kobling av en ny leverandørkonto etter fersk innlogging med en eksisterende identitet | **Utsatt til første tjeneste med `auto_link=0` / Fase 5** (012-analysen). Uten den avvises en bruker med `auto_link=0` som bytter konto (`account_not_linked`). Til da kobler admin fra den gamle identiteten (012), og neste konto kobles som første | ROADMAP Fase 2/5, ADN 13, ADN 14 |
| Selvbetjening: kontoside der brukeren selv ser, kobler og kobler fra identiteter | **Utsatt til første tjeneste med `auto_link=0` / Fase 5.** kauth har ingen brukerrettet kontoside. 012 gjør dette admin-styrt | ROADMAP Fase 5, ADN 14 |
| Varsel til gammel adresse ved e-postendring i admin | Admin går god for ny adresse (012 PB1). Et varsel, ikke en bekreftelse, ville gjort en kontoovertakelse via admin synlig for brukeren. Krever e-posttjenesten i admin og treffes av Brevo-allowlisten | ADN 14 |
| Knapp for en annen `konge` til å åpne admin-bindingen (`admin_bound_at`) | 012 bruker en driftsprosedyre (`sqlite3`). Kommer hvis prosedyren brukes mer enn sjelden (012 D3d) | ADN 14 |
| Stram inn overgangsunntaket for `auto_link=0` | **Utsatt til første tjeneste med `auto_link=0` / Fase 5** (012-analysen). I dag kobles brukerens første identitet på e-post. Vurder f.eks. fersk magic link som krav. Merk at frakobling av alle identitetene (012) åpner unntaket igjen for brukeren | ADN 13, ADN 14 |
| Admin-vinduet: `konge`-brukere som ikke har logget inn i admin med Google etter deploy | Godkjenn (én innlogging) eller fjern `konge`. Til da kan en kobling via en tjeneste med `auto_link=1` bli første admin-identitet (011 F3, PD8b). 012 endrer ikke dette (PB2), men etter første godkjenning lukkes vinduet for godt (`admin_bound_at`) | ADN 13, ADN 14 |
| ~~`RevokeUserRefreshTokens`: fjern `OR email`~~ | Tas i 012 (K13). 0 rader uten `user_id` i prod 2026-10-15, ingen backfill | ADN 14 |
| `user_id`-FK uten `ON DELETE`, og trigger mot `UPDATE` av `public_id` | **Utsatt til GDPR-sletting** (ikke 012). Avgjøres når sletting av brukere kommer (011 F1) | ADN 13 |
| `err.Error()` i admin-feilmeldinger ved opprettelse og lagring av tjeneste (`services.go`) | Fantes fra før. Internfeil kan lekke til admin-siden (011 F4, security) | ROADMAP M7 |
