# Funksjonalitet i kauth

En komplett oversikt over hva kauth gjør og hvordan. README-en gir overordnet motivasjon; dette dokumentet gir detaljen.

## Innholdsfortegnelse

- [Innloggingsmetoder](#innloggingsmetoder)
- [Identitetsmodell](#identitetsmodell)
- [Token-håndtering](#token-håndtering)
- [OIDC authorization_code + PKCE](#oidc-authorization_code--pkce)
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

Fire innebygde metoder, valgbare per tjeneste via boolean-felter i `services`-tabellen (`auth_google`, `auth_microsoft`, `auth_magic_link`, `auth_password`). I tillegg kan en tjeneste ha generiske OIDC-leverandører (se [Generisk OIDC](#generisk-oidc)), som tilordnes i `service_identity_providers` og ikke har et eget flagg.

Alle metodene, også generisk OIDC, går gjennom samme utstedelse: `checkPolicy`, access- og refresh-token, refresh-cookie, rydding av state-cookie (bare de fødererte: `oidc_state`, `ms_state` og `idp_state`), `last_login`, suksess-audit og redirect til `/dispatch`. Google, Microsoft og generisk OIDC deler i tillegg en føderert sti for state, avvisning og resolverfeil (ADN 16). Verifiseringen av id_token er hos hver leverandør. Admin-Google bruker ikke utstedelsen.

### Google OIDC

Standard OAuth2-flyt med signert state. kauth er konfidensiell klient med hemmelighet og bruker ikke PKCE mot Google. Nonce sendes til Google og sjekkes mot `id_token.nonce`. `email_verified == true` kreves i både vanlig og admin-gren; ellers avvises innloggingen og `google_oidc_rejected` logges i audit. Per-tjeneste OAuth-klient hvis `google_client_id` er satt på service-raden, ellers global klient fra miljøvariabler. Redirect-URI bygges per request fra `Host`-headeren, slik at ulike auth-hostnames kan registreres mot ulike Google-klienter med presise whitelists.

### Microsoft OIDC

Bruker `/common/oauth2/v2.0`-endepunktet for å akseptere både personlige Microsoft-kontoer og bedriftskontoer. Signaturen valideres mot kanonisk JWKS-URL: `https://login.microsoftonline.com/common/discovery/v2.0/keys`. Biblioteket kjører med `SkipIssuerCheck`, fordi `iss` er per tenant. kauth sjekker i stedet selv at `iss` er `https://login.microsoftonline.com/{tid}/v2.0` (ADN 10).

- Personlig konto (MSA) gjenkjennes bare på `tid == 9188040d-6c67-4c5b-b112-36a304b66dad`. Et manglende claim tolkes aldri som personlig konto.
- Organisasjonskonto krever `xms_edov == true`. `xms_edov` er optional claim i app-registreringen, og er konfigurert i begge Entra-appene (Klarsyn og spekto).
- Tom `email` avvises. Det er ingen fallback til `preferred_username`.
- Nonce sendes til Microsoft og sjekkes mot `id_token.nonce`.
- Avvisning logges som `microsoft_oidc_rejected` med `reason=<årsak>` og `tid` i details.
- Feil i kodeutvekslingen og i verifiseringen av id_token logges som `microsoft_oidc_rejected` med `reason=code_exchange` eller `reason=id_token`, uten e-post og `tid`.
- kauth bruker ikke PKCE mot Microsoft. Klienten er konfidensiell og har hemmelighet. Innloggingen bindes med signert state og nonce.

### Generisk OIDC

Innlogging mot en konfigurerbar OIDC-leverandør (015, ADN 17). Leverandørene er rader i `identity_providers`, tilordnet tjenester i `service_identity_providers` (med `position` for rekkefølge). Hver tilordnet leverandør gir en knapp «Fortsett med <navn>» på login-siden, etter Microsoft og før magic link. Uten tilordning er login-siden uendret. Google og Microsoft ligger utenfor tabellen. Driftsprosedyre: [IDENTITY_PROVIDERS.md](IDENTITY_PROVIDERS.md).

- **Flyt:** `GET /idp/{slug}/login` og `GET /idp/{slug}/callback`. Authorization code med PKCE S256 (verifieren utledes med HMAC fra state, ingenting lagres), nonce og signert state med slug. Slug i stien må være lik slug i staten, og tjenesten kommer fra staten, aldri fra stien. Redirect-URI er `https://<Host>/idp/<slug>/callback`.
- **Lasting:** en rad lastes bare når den er aktiv, har gyldig slug og visningsnavn, og issueren står eksakt i `KAUTH_OIDC_ISSUERS` (andre nøkkel), er `https://` og ikke Google eller Microsoft. `client_secret_env` må starte med `KAUTH_IDP_` og peke på en ikke-tom variabel, `scopes` må ha `openid`, og `trust_email=1` krever `email_domains`. En avvist rad logges (`idp: leverandør ikke lastet`) og tar ikke ned oppstarten. Alt leses ved oppstart, så endringer krever restart.
- **Utgående klient:** discovery, JWKS og token-endepunkt går via én låst klient: bare https, ingen redirect, 10 s, 1 MiB, og dial-vakt mot loopback, private og andre ikke-offentlige adresser (også NAT64, 6to4 og Teredo). Discovery og JWKS caches per leverandør (24 t, stale-while-revalidate, gammel verdi gyldig i 7 døgn, negativ cache 60 s).
- **id_token:** signaturen verifiseres mot leverandørens JWKS med snittet av annonserte algoritmer og RS/PS/ES/EdDSA (aldri HS256 eller `none`). `iss`, `aud`, utløp, nonce og `azp` (når satt) sjekkes. `iss`-parameteren i tilbakeruten kreves når leverandøren annonserer RFC 9207. Bare et id_token fra token-endepunktet (back-channel) verifiseres.
- **E-posttillit:** `trust_email=0` (standard) gir innlogging bare for allerede koblede identiteter. `trust_email=1` krever `email_verified`, ren ASCII-adresse med én `@` og et domene i `email_domains` (eksakt, uten subdomener). Mangler ett vilkår, er innloggingen som ved `trust_email=0`. ASCII-kravet finnes fordi `NormalizeEmail` bretter unicode.
- **Identitet:** `(issuer, subject)` med `provider='oidc'` i `user_identities`. Samme `sub` hos to leverandører er to identiteter. En generisk identitet gir aldri `admin_ok` og går aldri gjennom admin-stiene.
- **Audit:** `oidc_login` ved suksess (`auth_method=oidc`) og `oidc_rejected` ved avvisning, med `provider=<slug> reason=<kode>`. Årsakene er `unknown_service`, `unknown_provider`, `provider_error`, `issuer_param`, `discovery`, `code_exchange`, `id_token_missing`, `id_token`, `nonce`, `missing_sub`, `email_missing`, `email_untrusted`, `user_inactive`, `user_conflict` og `internal`. Teksten fra leverandøren havner aldri i svaret til brukeren.
- **Testleverandør:** `cmd/kauth-testidp` (bygges med `make testidp`, ikke del av prod-binæren) brukes av eval-serveren sammen med `KAUTH_OIDC_ALLOW_INSECURE=true`.

### Leverandøradmin og koblingsinvitasjon

Fra 016 (ADN 18). Admin ser leverandørene, styrer tilordning per tjeneste uten omstart og kobler generiske identiteter via en invitasjon brukeren selv fullfører. Drift: [IDENTITY_PROVIDERS.md](IDENTITY_PROVIDERS.md).

- **Leverandørside:** `GET /admin/providers` viser alle rader i `identity_providers` med status (lastet, inaktiv eller avvist med årsak), allowlist, `trust_email`, navnet på hemmelighetsvariabelen og om den er satt (aldri verdien), og tilordnede tjenester. Bare lesende. Ingen rute endrer leverandørrader.
- **Tilordning:** `POST /admin/services/{id}/providers` erstatter tjenestens tilordninger i én transaksjon og laster registeret om uten omstart. Bare lastede leverandører kan legges til. Tilordninger til ikke-lastede beholdes og kan fjernes eksplisitt. Auditeres synkront som `service_providers_updated`.
- **Identitetslisten:** brukersiden viser leverandørnavn i stedet for «oidc», og «ukjent leverandør» når raden er borte.
- **Invitasjon:** `POST /admin/users/{id}/link-invites` sender en engangslenke (24 t, SHA-256-hash i `identity_link_invites`, maks 5 per bruker per time) til brukerens adresse. En ny invitasjon for samme bruker og leverandør brenner den forrige. `POST /admin/users/{id}/link-invites/{inviteID}/revoke` trekker tilbake. Deaktivering og e-postendring brenner åpne invitasjoner.
- **Brukerflyt:** `GET /link/{token}` viser en bekreftelsesside med maskert e-post og endrer ingenting. `POST /link/{token}` (samme origin) sender brukeren til leverandøren med PKCE, nonce, signert state (`link=<id>`) og `prompt=login`. I `/idp/{slug}/callback` bindes `(issuer, sub)` til invitasjonens bruker i én transaksjon etter at all vanlig verifisering er gjort. `admin_ok` settes aldri, og det utstedes ingen tokens eller sesjon. Brukeren får kvitteringsside og kvitteringsmail. Ugyldige lenker gir samme generiske side. Sidene sender `Referrer-Policy: no-referrer` og `Cache-Control: no-store`.
- **Audit:** `identity_link_invited`, `identity_link_invite_revoked`, `identity_linked` med `via=invite`, og `identity_link_rejected` med `reason=invite_invalid|user_inactive|email_changed|identity_taken|discovery|internal`. Koblingsaudit skrives synkront. Token og `sub` står aldri i audit eller logg.

### Magic-link på e-post

256-bit kryptografisk tilfeldig token i en lenke, 15 minutters levetid, engangsbruk via atomisk `UPDATE WHERE used = 0`. Tokenet lagres som SHA-256-hex (`HashOpaque`), aldri i klartekst. Klartekst finnes bare i e-posten.

- **Bestilling (`POST /magic-login`):** e-posten normaliseres (`NormalizeEmail`: trim + små bokstaver) før alt annet. Kvoten er 3 bestillinger per normalisert e-post og formål (`service`/`admin`) per 15 minutter. Den telles i databasen i samme `INSERT`, så den overlever restart og holder under parallelle forespørsler. Er kvoten brukt opp eller lagringen feiler, sendes ingen e-post. Svaret er likevel det samme (se Anti-enumeration). Sending skjer asynkront, slik at responstiden ikke skiller kjente fra ukjente adresser
- **Tjenestebinding:** raden lagrer tjenesten som ble resolvet ved bestilling, ikke skjemaverdien. Er `auth_magic_link` av for tjenesten, settes ingen rad inn. Ved innløsning brukes bare den lagrede tjenesten, uansett `?service=` eller host. Er tjenesten inaktiv eller har magic link av da, gir det `error=expired`, og tokenet brennes
- **Bekreftelsesside:** lenken i e-posten åpner `GET /magic-login/{token}`, som bare viser en side med én knapp. Siden har tjenestens tema, nb/en/de, ingen e-postadresse og ingen JavaScript. GET endrer ingenting og teller ikke i kvoten, så lenkeskannere og forhåndsvisning i e-postklienter bruker ikke opp tokenet. Knappen sender `POST /magic-login/{token}`, som bruker opp tokenet og logger inn. Ukjent, utløpt eller brukt token gir `error=expired`
- **Samme origin:** POST krever samme origin (se Sec-Fetch under Sikkerhetsmekanismer). Et kryss-origin-forsøk gir `403` med en forklaring («åpne lenken i nettleseren»), og tokenet står urørt
- **SMTP:** e-post sendes med 10 s dial-timeout og 30 s frist for hele samtalen, så en hengende server ikke samler goroutiner. STARTTLS brukes når serveren tilbyr det, og `KAUTH_SMTP_STARTTLS` krever det. Brevo-API-et har fortsatt egen tidsgrense på 10 s
- **Formål:** `magic_tokens.purpose` skiller tjenestelenker (`service`, med `service_id`) fra admin-lenker (`admin`, uten `service_id`). Et token kan ikke brukes på feil side

### Passord

Deaktivert som standard. bcrypt-hashet, lagres i `password_hash`. OIDC-only-brukere får sentinel-verdien `"n/a"` i feltet. Se argumentet for passordfri-default i hoved-README.

## Identitetsmodell

E-post er et attributt på brukeren, ikke identiteten (ADN 13). Identiteten til en føderert innlogging er `(issuer, subject)` i tabellen `user_identities`, unik og knyttet til én bruker.

- **Google:** issuer er alltid `https://accounts.google.com` (også når `iss` kommer uten `https://`), subject er `sub`.
- **Microsoft:** issuer er `https://login.microsoftonline.com/{tid}/v2.0` med `tid` i små bokstaver, subject er `oid` i små bokstaver. `oid` er påkrevd og må være en GUID, ellers avvises innloggingen (`microsoft_oidc_rejected reason=missing_oid`). `sub` brukes ikke, fordi den er parvis per Entra-app.
- **Generisk OIDC:** issuer er issueren i `identity_providers`, ordrett. Subject er `sub`, maks 255 tegn.
- **Magic link og passord** lagrer ingen identitet. De bruker `users.email`.
- **`public_id`:** hver bruker har en UUID v4 (`users.public_id`, `crypto/rand`) som aldri endres.

**Oppslag ved innlogging:**
1. Er identiteten kjent, brukes brukeren den er koblet til, også når e-posten i claimet er en annen. Er brukeren deaktivert, avvises innloggingen. Endret e-post hos leverandøren endrer ikke `users.email`, men gir audit `identity_email_mismatch`.
2. Ellers slås brukeren opp på normalisert, leverandørbekreftet e-post, og identiteten kobles (`identity_linked`, `details` `provider= issuer= transition=`). `transition=1` betyr brukerens første identitet.
3. Finnes ingen bruker, registreres en ny hvis tjenesten har `auto_register`. Bruker og identitet opprettes i én transaksjon.

**`auto_link` (per tjeneste, default 1):** med 1 kobles en ukjent identitet til brukeren med samme e-post. Med 0 kobles bare brukerens første fødererte identitet (overgangsunntaket fra e-postmodellen), og koblingen er en atomisk betinget `INSERT`. Har brukeren allerede en identitet, avvises en ny konto med `?error=account_not_linked` på innloggingssiden (nb/en/de) og audit `identity_link_denied`. Teksten sier ingenting om hvilken konto som finnes. Koblinger er globale for brukeren, så `auto_link=0` beskytter bare innlogging via den tjenesten. Admin kan koble fra identiteter (se under). Eksplisitt kobling og selvbetjening venter til første tjeneste med `auto_link=0`.

**Admin-godkjent identitet:** admin-innlogging med Google registrerer aldri brukere og kobler bare brukerens første identitet (overgangsunntaket, som `auto_link=0`). Den godtar bare en identitet med `user_identities.admin_ok = 1`. Første admin-Google-innlogging, etter `konge`-sjekken, godkjenner identiteten (`identity_admin_approved`, `bound=1`) hvis brukeren ikke er bundet fra før (se «Admin-bindingen»). Andre kontoer avvises deretter (`identity_link_denied reason=not_admin_identity`), også de som er koblet via en tjeneste med `auto_link=1`. Admin via magic link er uendret.

**`sub_format` (per tjeneste, `email` eller `id`):** styrer hva `sub` er i access- og id_token. `email` (default) er som før. `id` gir brukerens `public_id`. `email`-claimet er med i begge tilfeller. Bytte er en kontraktsendring for klienten, som må godta `sub` som UUID og matche eksisterende brukere på `email` første gang. Admin-token og `/api/me` er uendret.

**Sesjoner:** refresh-tokens og autorisasjonskoder har `user_id`. Rotasjon arver det, og innløsning slår opp brukeren på `user_id`. En rad uten `user_id` behandles som inaktiv bruker, uten e-post-fallback: refresh revokerer familien (`user_inactive`), og kodeinnløsning gir `invalid_grant`.

### Frakobling

`POST /admin/users/{id}/identities/{identityID}/unlink` sletter én rad i `user_identities`, betinget på både identitets-ID og bruker-ID (en ID fra en annen bruker gir 404). Samme transaksjon revokerer alle refresh-familiene til brukeren (`identity_unlinked`). Feiler revokeringen, står identiteten. Audit `identity_unlinked` har `provider`, `issuer`, `admin_ok` og `revoked` i `details`, og `actor=` fra admin. Subject logges ikke. Deaktiverte brukere kan kobles fra.

Frakobling er et ryddeverktøy og ingen blokkering. Med `auto_link=1` kobles kontoen igjen ved neste innlogging hvis e-posten stemmer. Er alle identitetene koblet fra, gjelder overgangsunntaket for `auto_link=0` igjen. Mot en kompromittert konto hjelper det ikke å koble fra alene. Deaktiver brukeren.

### E-postendring

`POST /admin/users/{id}/email` setter ny e-post på brukeren. Admin går god for adressen, og det sendes ingen bekreftelseslenke. Skjemaet har en advarsel: tjenester med `sub_format=email` ser brukeren som en ny bruker etter endringen, så den skal avtales med tjenesteeieren. Avkrysningen «Jeg har avtalt endringen med tjenesteeierne» kreves, både i malen og på serveren (mangler den, gis 422 uten skriving). Endrer admin sin egen adresse, logges admin ut.

Adressen normaliseres og valideres. Samme adresse etter normalisering gir 422, en adresse i bruk gir 409, og en samtidig endring gir 409 («prøv igjen»). I én transaksjon skjer dette:
1. Alle refresh-familiene til brukeren revokeres (`email_changed`).
2. `users.email` og `email_changed_at` oppdateres, betinget på at gammel e-post er uendret.
3. Ubrukte magic-tokens for gammel og ny adresse brennes (`used = 1`, så kvoteradene står).

Audit `user_email_changed` har ny adresse i `email` og `id=… old=<gammel> revoked=<n> burned=<m>` i `details`. Identitetene (`issuer`, `subject`) og `user_identities.email` røres ikke. Magic link følger `users.email`.

Skjemaet sier at brukeren logges ut av alle tjenester. Det betyr revokerte refresh-familier og brente magic-tokens. Autorisasjonskoder (TTL 60 s) brennes ikke. En kode utstedt rett før endringen kan derfor løses inn i inntil 60 sekunder etterpå, og gir da en ny sesjon med vanlig levetid for samme bruker. Det samme gjelder frakobling. Deaktivering stopper også kodene, fordi innløsningen krever en aktiv bruker. Access-tokens hos klientene lever ut sin TTL (ADN 12).

### E-postepoken

Et signert token som identifiserer brukeren med e-post, godtas bare når `iat >= coalesce(email_changed_at, created_at)` for brukeren oppslaget fant. Det gjelder access-token på alle nivåene i `/dispatch` og admin-tokenet. På nivå 1–5 slipper tokenet gjennom ved DB-feil (ADN 15). Et token den gamle eieren av en adresse fikk, virker dermed ikke hos den nye eieren.

- Sammenligningen er på sekundnivå. Et token utstedt i samme sekund som epoken godtas.
- Epoken tolkes fra `2006-01-02T15:04:05Z` eller SQLite `datetime()`. Alt annet, og manglende `iat`, avvises.
- `/dispatch` avviser med audit `dispatch_subject_mismatch` (`level=0 reason=email_reassigned` eller `level=1-5 reason=email_reassigned`) og sender brukeren til `/login`. På nivå 1–5 er sjekken et konsistenslag og ingen tilbaketrekking (ADN 15): den som har tokenet, kan fortsatt gå rett til tjenestens callback. Admin avviser med 303 til `/admin/login` (401 med JSON når requesten ber om JSON), og logger bruker-ID-en.
- Går serverklokka bakover, kan epoken ligge i fremtiden. Brukeren avvises da til klokka har tatt den igjen. Preflight feiler hvis en epoke ligger i fremtiden.

### Admin-bindingen

`users.admin_bound_at` settes ved første admin-Google-innlogging etter `konge`-sjekken. En betinget `UPDATE … WHERE admin_bound_at IS NULL` og `SetAdminOK` kjører i samme transaksjon, og identiteten får `admin_ok = 1` bare hvis bindingen traff. Er brukeren bundet fra før, avvises innloggingen (`reason=not_admin_identity`). Forsvant identiteten mellom oppslaget og godkjenningen, rulles bindingen tilbake (`reason=identity_vanished`). Deretter godtar admin-Google bare den godkjente identiteten. Migrasjon 011 bandt brukerne som allerede hadde en `admin_ok`-identitet. Brukersiden i admin viser «Admin-Google er bundet <dato>», og sier fra når ingen identitet lenger er godkjent.

Appen nullstiller aldri `admin_bound_at`, heller ikke ved frakobling eller e-postendring. Mister brukeren den godkjente Google-kontoen, virker admin via magic link som før, men en ny Google-konto krever recovery-prosedyren under. Frakobling og e-postendring setter aldri `admin_ok`.

### Recovery

kauth har ingen egen mekanisme for recovery. En `konge` gjør stegene i admin. Stegene med `sqlite3` krever skall på prod-boksen og kjøres fra `~/kauth-go`. Noter hvert slikt inngrep.

| Situasjon | Prosedyre |
|---|---|
| Brukeren har mistet Google- eller Microsoft-kontoen | Admin kobler fra identiteten. Brukeren logger inn med magic link, eller med en ny konto (kobles på e-post med `auto_link=1`, og som første identitet med `auto_link=0` hvis alle gamle er koblet fra) |
| Kontoen er kompromittert | Deaktiver brukeren. Det revokerer alle familiene og stopper magic link, kodeinnløsning og innlogging. Frakobling alene stopper ikke en angriper som har innboksen. Når saken er avklart: endre e-post hvis innboksen var kompromittert, koble fra identitetene angriperen kan ha, og reaktiver i DB (admin har ingen reaktivering): `sqlite3 data/kauth.db "UPDATE users SET deactivated_at = NULL WHERE id = <id>"` |
| Brukeren har mistet tilgang til e-postadressen | Admin endrer e-posten. Si fra til tjenesteeierne for `email`-tjenester. Har noen andre fått innboksen, kobler admin også fra identitetene med den gamle adressen. En koblet identitet slås opp på `(issuer, subject)` og virker uansett e-post |
| En adresse skal gis til en ny person | Endre den gamle brukerens e-post til en adresse som ikke leveres, for eksempel `avsluttet-<id>@kauth.invalid`, og deaktiver brukeren. Bruk ikke en plussadresse på samme postkasse (`navn+avsluttet@domene`): den går til innboksen den nye personen får, og gir magic link til den gamle brukeren. Koble fra identitetene hvis den nye personen skal bruke samme leverandørkonto. Ellers slås kontoen opp til den gamle, deaktiverte brukeren og avvises. Opprett den nye brukeren. Epoken hindrer at tokens fra den gamle eieren virker |
| En `konge` har mistet sin admin-godkjente konto | Logg inn i admin med magic link og koble fra den gamle identiteten. Den nye Google-kontoen må ha brukerens e-post. Admin-innloggingen kobler den bare som første identitet, så enten logger brukeren inn med den på en tjeneste med `auto_link=1` først, eller så kobles alle identitetene fra. Åpne bindingen: `sqlite3 data/kauth.db "UPDATE users SET admin_bound_at = NULL WHERE id = <id>"`. Logg inn i admin med den nye Google-kontoen **straks**. Til da står bindingen åpen, og enhver konto koblet til brukeren kan bli godkjent, også en som er koblet via en tjeneste med `auto_link=1` |

**Utolkbar epoke.** Får en bruker avvisning i admin eller på `/dispatch` uten at noe er endret, og journald viser «e-postepoke kan ikke tolkes» for bruker-ID-en, er epoken (`email_changed_at`, eller `created_at` når den er NULL) i et format `ParseEpoch` ikke kjenner. Nødprosedyren setter epoken til nå:

```bash
sqlite3 data/kauth.db "UPDATE users SET email_changed_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = <id>"
```

Den er alltid trygg. Eldre tokens for brukeren avvises på `/dispatch` og i admin, så brukeren må logge inn der på nytt. `email_changed_at = NULL` lar epoken falle tilbake til `created_at` og gir ingen ny innlogging, men passer bare når feilen sitter i `email_changed_at`, `created_at` er tolkbar, og ingen annen bruker har hatt adressen etter brukerens `created_at`. Ellers kan et token fra en tidligere eier av adressen bli godtatt igjen. Preflight (`scripts/identity-preflight.sh data/kauth.db`) feiler på utolkbare epoker og epoker i fremtiden, og kjøres før deploy.

**Rollback:** rull tilbake binæren. Kjør aldri `goose down` for migrasjon 011 (`011_admin_identity.sql`) etter at frakobling er brukt. En ny `Up` binder bare brukere som fortsatt har en `admin_ok`-identitet. Ved ny deploy etter en rollback kjøres backfill-`UPDATE`-en fra migrasjonen på nytt før restart. Ellers står en `konge` som ble godkjent mens den gamle binæren kjørte, ubundet.

## Token-håndtering

### JWT (access token)

RS256-signerte. Claims:
- `sub` — brukerens e-post (`sub_format=email`, default) eller brukerens `public_id` (`sub_format=id`), se Identitetsmodell
- `email`
- `org` — array av tenant-slugs fra `users.orgs` (CSV-felt i DB, splittes ved utstedelse)
- `groups` — array fra `users.roles`
- `name` — valgfri
- `token_use` — `access`, `id` eller `admin`
- standard `iss`, `iat`, `exp`, `nbf`
- `aud` — tjeneste-ID for access- og id_token (`["<svc.ID>"]`), `["kauth-admin"]` for admin-token. Gjelder alle innloggingsmetoder, `authorization_code`-flyten og refresh. Et refreshet token får tjenesten fra familiens lagrede rad, aldri fra requesten
- `jti` — 128 bit fra `crypto/rand` (base64url) på alle signerte tokens (access, id, admin). Ikke lagret. Brukes til korrelasjon i audit og er grunnlaget for en senere denylist

`id_token` har `aud=[svc.ID]`, `token_use=id` og `nonce` fra autorisasjonsforespørselen. Klientene må sjekke `token_use` (og `nonce` for id_token), siden access- og id_token har samme `aud`. En klient godtar `aud` som streng eller array. Kauth sjekker `aud` selv i `/dispatch` (se Dispatcher-routing), men en ressursserver som bare validerer signatur og `iss` godtar fortsatt et token for en annen tjeneste. Hver klient krever `aud` i en egen leveranse (se BACKLOG).

TTL settes per tjeneste via `services.access_token_ttl` (ISO 8601-varighet, f.eks. `PT15M`, `PT8H`, `P1D`).

### JWKS + OpenID Discovery

- `GET /.well-known/jwks.json` — eksponerer nøkkelringen: current først, så next og previous (bare de som er satt), hver med `kty=RSA, use=sig, alg=RS256, kid`
- `GET /.well-known/openid-configuration` — standard discovery-dokument med `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `response_types_supported`, etc.
- Resource-servere validerer JWT mot JWKS-URL. Rotasjon oppdages **ikke** automatisk: klienter cacher JWKS (pov: 1 t) og henter ikke på nytt ved ukjent `kid`, så rotasjon følger prosedyren i [KEY_ROTATION.md](KEY_ROTATION.md)
- **`kid`:** alle JWT-er (access, admin) har `kid` i headeren, lik current-nøkkelen (`KAUTH_SIGNING_KID`, default `kauth-1`). Klienter skal velge nøkkel etter `kid`
- **Nøkkelring (017):** current signerer; next er bare publisert (så klienter rekker å hente den); previous er publisert og godtatt i `Verify` så tokens fra forrige nøkkel lever ut TTL-en. `Verify` velger etter `kid` blant current og previous, og prøver uten `kid` current og så previous (bare ved signaturfeil). Ukjent `kid`, `kid` = next og andre algoritmer enn RS256 avvises. Feil konfig stopper oppstarten
- **Klienthemmeligheter (017):** Google/Microsoft-hemmeligheten per tjeneste kan ligge som navn på en miljøvariabel (`KAUTH_SVC_*`) i stedet for klartekst i databasen. Referansen vinner over kolonnen, kolonnen over global env. Tom variabel gir `login_failed` for den metoden, uten fallback. Se [KEY_ROTATION.md](KEY_ROTATION.md)

### Refresh-token-rotasjon

256-bit opake tokens, lagret SHA-256-hashet (`refresh_tokens.token_hash`, 64 hex-char CHECK-constraint). Hver utstedelse skaper en ny familie eller arver eksisterende `family_id`. `POST /token?grant_type=refresh_token` roterer i én transaksjon:

1. Token konsumeres atomisk (`used = 1`) og barnet settes inn i samme transaksjon. Feiler en av delene, er ingenting endret
2. Ny access-JWT + ny refresh-token utstedes med samme `family_id`
3. Eksisterende refresh-cookie overskrives

Feil gir ulik status: klientfeil (ukjent, utløpt, revokert eller gjenbrukt token) gir 401, mens interne feil (DB, tilfeldighetskilde, cache) gir 500 `server_error`. Ved 500 beholder klienten cookien og kan prøve igjen.

### Revokering av refresh-familier

Familien er enheten for tilbaketrekking (ADN 10). Hele familien revokeres (`RevokeFamilyTokens`) når:

- **Reuse:** et konsumert token presenteres igjen. Sjekken er uavhengig av `used`-flagget og av klientens request-context, slik at revokeringen fullføres selv om klienten kobler fra. Audit `refresh_token_reuse` får `service_id` og `gap_s=<sekunder>` fra barnets opprettelse til gjenbruket (`gap_s=unknown` hvis barnet mangler). Lite gap tyder på klient-race, stort gap på stjålet token. Gapet er grunnlaget hvis et idempotensvindu noen gang skal vurderes
- **Revokert token presenteres:** familien tas ned på nytt (revoked_reason `revoked_token_presented`) og audit `refresh_token_revoked_presented` logges. Utløpt-men-ikke-revokert token gir bare avvisning
- **Logout:** `GET /logout` revokerer familien til `refresh_token`-cookien (`user_logout`) før cookien slettes, men bare når forespørselen er en bevisst handling (se Logout og Sec-Fetch under Sikkerhetsmekanismer)
- **Verifisert gjenbruk av autorisasjonskode:** familien koden ga opphav til revokeres (`authorization_code_reuse`) bare når klient, `redirect_uri` og PKCE matcher, se OIDC-delen
- **Deaktivering:** admin-deaktivering av en bruker revokerer alle brukerens refresh-tokens (`user_deactivated`)

Klienten får generisk avvisning, og hele kjeden er død for både angriper og legitim klient. Et ekte refresh-race logger derfor ut begge parter. Matcher OAuth Security BCP (RFC 9700 §4.14.2).

**Akseptert begrensning:** allerede utstedte access-tokens lever til TTL utløper etter logout eller deaktivering. `/api/me` validerer bare JWT-en og sjekker ikke databasen. Kortvarig TTL er den eneste avgrensningen.

### Per-tjeneste TTL og max-age

- `services.access_token_ttl` — JWT-levetid
- `services.refresh_token_max_age` — hardt tak på familielevetid (NULL = ubegrenset)
- `family_expires_at` settes ved første utstedelse fra `max_age`, arves uendret ved hver rotasjon; klempes på `min(now+30d, family_expires_at)` ved utstedelse

## OIDC authorization_code + PKCE

Løser inn en klar mangel i den ellers OIDC-flavored bespoke flyten over:
et standard OIDC-klientbibliotek (`oidc-client-ts`, `authlib` osv.) kan ikke
brukes mot `/login`+`/dispatch` slik de fungerte alene — token kom tilbake
direkte i URL-en, uten `nonce` og uten en `code`-runde å bytte inn. Dette
er nødvendig for en klient kauth ikke selv kontrollerer kildekoden til.

### Forespørselen (`/login` som authorization_endpoint)

En standard OIDC-forespørsel gjenkjennes på `response_type=code&client_id=...`.
`client_id` er samme verdi som tjenestens `services.id` — det finnes ingen
egen klient-tabell, en OIDC-klient ER en tjeneste. Ved en slik forespørsel:

1. Tjenesten resolves på `client_id` (ikke `?service=` eller host-header).
   Ukjent `client_id` → 400 direkte fra kauth, ikke en redirect (det ville
   vært en open redirect via en påfunnet client_id — kauth har ingen
   betrodd redirect_uri å sende brukeren til før client_id er slått opp)
2. `redirect_uri` må matche tjenestens `callback_url`-allowlist eksakt
   (samme `Registry.IsAllowedCallback` som Google-flyten bruker). Ikke
   registrert → 400, av samme grunn som over
3. **PKCE er obligatorisk for enhver `response_type=code`-forespørsel —
   ingen per-tjeneste unntak.** `code_challenge` og
   `code_challenge_method=S256` må begge være til stede, ellers redirectes
   brukeren til `redirect_uri?error=invalid_request&state=` (RFC 6749
   §4.1.2.1 — redirect_uri er jo allerede bekreftet trygg i steg 2, så feilen
   rapporteres dit, ikke som en 400 kauth selv viser fram). Det finnes ingen
   konfidensiell klient-type i det hele tatt: `client_id` er offentlig
   informasjon, og en kode uten PKCE ville kunnet løses inn av hvem som
   helst som fanget den opp underveis
4. Hele forespørselen (client_id, redirect_uri, state, nonce, scope,
   code_challenge, code_challenge_method) lagres i en **usignert**
   `oidc_authz`-cookie og bæres videre gjennom resten av innloggingsreisen —
   magic link, Google, Microsoft eller passord er alle uendret og ser
   ingenting av dette

En vanlig (ikke-OIDC) `/login`-forespørsel rydder proaktivt en eventuell
gjenværende `oidc_authz`-cookie fra en tidligere avbrutt OIDC-runde — se
"To lag forsvar" under.

### Autorisasjonskoder

`authorization_codes`-tabellen speiler `magic_tokens` (koden lagres som SHA-256-hex, klartekst går bare i redirecten): kortlevd (60 sekunder
— vesentlig kortere enn magic-link sine 15 minutter, siden koden kun skal
leve fra `/dispatch`-redirect til klientens umiddelbare innløsning) og
engangsbrukt (`used`-flagg, samme "konsumer atomisk"-mønster som
`ConsumeMagicToken`). `code_challenge`/`code_challenge_method` er `NOT NULL`
i skjemaet — reflekterer at PKCE aldri er valgfritt.

`/dispatch` genererer koden idet en `oidc_authz`-cookie er til stede (etter
at brukeren har fullført innlogging via en av de vanlige metodene), og
redirecter til `redirect_uri?code=&state=` (bygget med `url.Parse` +
`Query().Set`, ikke strengkonkatenering — en registrert redirect_uri kan
allerede ha egne query-parametre) — aldri med et token i klartekst i URL-en,
i motsetning til den eksisterende bespoke flyten.

#### Hvorfor tilgangsreglene håndheves i `/token`, ikke i `/dispatch`

Første forsøk på denne herdingen la en `?service=`-sjekk i `/dispatch`: krev
at URL-ens `?service=`-parameter er identisk med `oidcReq.ClientID` før en
kode utstedes. Det viste seg utilstrekkelig, og verdt å forklare hvorfor,
siden feilen er lett å gjenta.

`?service=` er en vanlig URL-parameter — ikke en verdi bundet til tokenet.
Et vanlig access-token hadde den gangen ingen `aud`, så `/dispatch` kunne ikke
vite hvilken tjeneste et gitt token faktisk ble utstedt for; den kunne bare
lese hva URL-en *påstår*. En bruker med et helt legitimt token for tjeneste B (som de har
lovlig tilgang til) kunne derfor, mens en `oidc_authz`-cookie for tjeneste A
ligger fra tidligere (fra å ha klikket "logg inn" i partner-app A, uten å
fullføre den runden), gå rett til `/dispatch?token=<B-token>&service=A` —
uten noensinne å ha gått via A sin egen login-handler, der A sine
`require_role`/`enforce_org`-regler normalt håndheves. `?service=`-sjekken
passerer (URL-en er internt konsistent), og en A-kode utstedes til en
bruker som aldri har blitt vurdert mot A sine regler.

Løsningen: `/token` er stedet i flyten som kan vite sikkert
hvilken tjeneste som skal autorisere brukeren, fordi det er der `svc` slås
opp fra koden selv (`row.ServiceID`), ikke fra en URL-parameter klienten
kontrollerer. `authorizationCodeGrant` kaller derfor `checkPolicy(user, svc)`
— samme funksjon Google-flyten allerede bruker (`google.go`) — rett etter
`GetActiveUserByEmail`, og avviser med `invalid_grant` hvis brukeren mangler
`RequireRole` eller ikke er i `EnforceOrg`-organisasjonen. Dette gjelder
uansett hvor gyldig koden og PKCE-verifiseringen er.

`/login` rydder fortsatt en gjenlevende `oidc_authz`-cookie proaktivt i sin
ikke-OIDC-gren, og `/dispatch` beholder `?service=`-sjekken — begge er
fortsatt fornuftig hygiene og feiler trygt (retur til `/login` er aldri
skadelig), men ingen av dem er nå det som faktisk beskytter mot
tilgangsomgåelse. Det er `checkPolicy` i `/token` som gjør den jobben.

Fra 010 binder nivå 0 i `/dispatch` koden til tokenets `aud`. `checkPolicy` i `/token` er fortsatt eneste sted som evaluerer A sine regler mot dagens brukerdata.

### Innløsning (`POST /token`, `grant_type=authorization_code`)

`/token` dispatcher nå på `grant_type` (tidligere behandlet enhver
forespørsel som refresh). For `authorization_code`:

1. `code_verifier` sin lengde valideres (43-128 tegn, RFC 7636 §4.1) før den
   i det hele tatt brukes til noe
2. Koden slås opp på hash. Manglende `code` gir `invalid_request`, ukjent tjeneste `invalid_client`, ukjent kode generisk `invalid_grant` (audit `authorization_code_invalid`)
3. En kode som allerede er brukt, er gjenbruk (sjekkes før utløp og mismatch). Matcher klient, `redirect_uri` og
   PKCE, revokeres refresh-familien koden ga opphav til (`authorization_code_reuse`,
   OAuth BCP). Matcher de ikke, revokeres ingenting (`authorization_code_reuse` med `reason=unverified`),
   så en lekket kode alene ikke kan logge ut brukeren. Utløpt kode gir `authorization_code_invalid`
4. `client_id` og `redirect_uri` fra requesten må matche eksakt det koden
   ble utstedt for (RFC 6749 §4.1.3), og `code_verifier` hashes
   (SHA-256 → base64url) og sammenlignes mot lagret `code_challenge`. Kun
   `S256` støttes, `plain` tilbys bevisst ikke. Alltid håndhevet, ikke
   betinget av noe tjenesteflagg. Avvik gir `invalid_grant` og audit
   `authorization_code_mismatch` med `reason=client|redirect_uri|pkce`, og
   koden røres ikke: en angriper som bare gjetter, kan ikke brenne offerets kode
5. `checkPolicy(user, svc)` — samme funksjon Google-flyten bruker — kjøres
   på nytt mot tjenesten koden faktisk tilhører (`row.ServiceID`, ikke noen
   URL-parameter). Dette er den reelle beskyttelsen mot tilgangsomgåelse,
   se forklaringen over
6. Konsum og første refresh-rad skjer i én transaksjon (`ConsumeAuthorizationCodeChecked`, med alle predikater i `WHERE`). Koden får `family_id` fra den nye familien. Ved parallelle forsøk vinner høyst ett, og taperen klassifiseres som gjenbruk. Øvrige kodefeil gir `400 invalid_grant`, interne feil `500 server_error`
7. Ved suksess utstedes access- og refresh-token. Access-tokenet har `aud=[client_id]`, som alle andre access-tokens. Audit `authorization_code_exchanged` har `jti_access`, `jti_id` (`-` uten id_token) og `family` i `details`
8. `id_token` (`Issuer.IssueIDToken`, `aud`=client_id, `nonce` speilet fra
   requesten) utstedes KUN hvis scope inneholder `openid` (OIDC Core
   §3.1.3.3) — en ren OAuth2-klient som aldri ba om `openid` skal ikke få et
   identitetstoken den ikke forventer

**Ressursserveres eget ansvar:** kauth setter `aud` på alle access-tokens, men
om en intern ressursserver (minliste, bildegalleri, spekto, ...) faktisk
validerer `aud` er opp til den serveren selv. Sjekk dette før en tjeneste
faktisk åpnes for en ekstern OIDC-klient. Hvis ressursserveren kun validerer
signaturen, kan et token utstedt til partneren i prinsippet brukes mot den
også. Gjenbruk av en kode revokerer familien, men access-tokens som allerede
er utstedt lever ut TTL, siden klientene validerer lokalt. `jti` og `family` i
auditen gjør det mulig å se hvilke tokens det gjelder.

### Cleanup

Utløpte autorisasjonskoder ryddes av samme bakgrunnsjobb-mønster som magic
tokens og refresh tokens — se [Bakgrunnsjobber](#bakgrunnsjobber).

## Multi-tenant arkitektur

### Tjeneste-resolver

`internal/service.Registry` cacher alle aktive tjenester i minnet og resolver request → tjeneste via fire-nivå prioritet:

1. **Eksakt redirect_uri-host == service.domain** — vinner over auth_host. Wire/sub-tjenester deler auth-host med foreldretjenesten men har eget domain.
2. **Host-header == service.auth_host** — for tjenester med dedikert auth-hostname (auth.spekto.live, auth.lilleklo.work)
3. **Eksplisitt service-ID** via `?service=`-query
4. **Suffix-match redirect_uri mot service.domain** — for sub-domener uten egen service-rad

Cache invalideres ved Create/Update i admin-panelet.

**Eksplisitt tjeneste-ID og host (alle fire innloggingsmetoder).** Google, Microsoft, magic link (skjemafelt `service` med fallback `service_id`, `?service=` på GET og tema-hint) og passord (`service_id`) bruker samme regel (`resolveRequestedService`). Oppgitt ID vinner over host bare når tjenesten ikke har egen `auth_host`, eller når `auth_host` er akkurat denne hosten. Ellers brukes hostens tjeneste, uten nivå 3-sjanse. Ukjent ID faller også til hosten, og ukjent ID på ukjent host gir default-tjenesten. En undertjeneste uten egen `auth_host` (wspekto) kan derfor bindes fra enhver host, og policy, `aud` og callback følger den bundne tjenesten.

### Per-tjeneste branding

- `display_name`, `tagline`, `accent_color`, `theme` (light/dark)
- `logo_html` — rå SVG/HTML, embeddes via `template.HTML` cast
- `bg_image` — sti relativ til `/static/`, rendres som `url('/static/<sti>') center/cover no-repeat fixed`
- `bg_css` — alternativ ren CSS-bakgrunn

### Per-tjeneste OAuth-klienter

`google_client_id`/`google_client_secret`/`microsoft_client_id`/`microsoft_client_secret` overstyrer globale miljøvariabler. Lar ulike tjenester ha separate Google Cloud-prosjekter med presise redirect-URI-whitelists.

### Per-tjeneste auth-flagg

`auth_google`, `auth_microsoft`, `auth_magic_link`, `auth_password`, `auto_register`, `enforce_org`, `is_default`, `active`. Login-templaten viser kun knapper for aktive metoder.

I tillegg `sub_format` (`email`/`id`) og `auto_link` (0/1), se Identitetsmodell. Skjemaet i admin tar vare på lagret verdi når feltet mangler i innsendingen, og avviser ukjent `sub_format`.

### Default-org og krav-rolle

- `default_org` — CSV-streng som blir `users.orgs` for auto-registrerte brukere
- `default_role` — tilsvarende for `users.roles`
- `require_role` — tjenesten krever at brukeren har denne rollen i `roles` for å logge inn
- `enforce_org` — krever at brukeren har `default_org` i `orgs`

Håndheves av `checkPolicy` (`internal/auth/identity.go`), kalt fra alle fire
login-veiene (Google, Microsoft, magic-link, passord) samt fra
`authorization_code`-grant i `/token`. Matcher CSV-feltet nøyaktig per felt
(splittet på komma, ikke substring) — `require_role="admin"` godtar ikke en
bruker med kun `sysadmin` i `roles`
([issues/2](https://github.com/zral/kauth-go/issues/2)). Magic-link og
passord kalte den ikke i det hele tatt før dette ble rettet
([issues/3](https://github.com/zral/kauth-go/issues/3)) — funnet i
kodegjennomgangen av PR #1, siden `require_role`/`enforce_org` inntil da kun
var reelt håndhevet for Google/Microsoft-innlogging.

## Admin-panel

Beskyttede ruter under `/admin/*` med separat `admin_token`-cookie (egen JWT med `token_use=admin`). Krever rollen `konge` i `users.roles`. Middlewaren verifiserer JWT-en og slår deretter opp brukeren i databasen på hver request. Ukjent eller deaktivert bruker, manglende `konge` i DB-rollene og DB-feil gir avvisning (`303 /admin/login` eller `401`), aldri tilgang. En deaktivert admin mister dermed tilgangen umiddelbart, ikke først når JWT-en utløper. Alle ikke-sikre metoder under `/admin` krever samme origin.

Skrivehandlingene (`user_created`, `user_edited`, `user_deactivated`, `service_created`, `service_edited`) auditeres synkront etter at endringen er lagret, med `actor=<admin-e-post>` i `details`. Feiler audit-skrivingen, står endringen, og redirecten får `?warn=audit` slik at listen viser «Lagret, men ikke auditert». Skjemafelt leses bare fra POST-body (`PostFormValue`), aldri fra query.

### Innlogging

- `GET /admin/login` — viking-door bakgrunn, primær Google-knapp + sekundær e-postlenke
- `GET /admin/google-init` — starter vanlig Google-flyt mot samme `/callback` (samme URL som er hvitlistet hos Google), men med admin-formål i den HMAC-signerte state-parameteren. Formålet hentes aldri fra query, cookie eller `redirect_uri`, og flyten går ikke innom `/dispatch`
- `GET /admin/google-callback` — utgått inngang som ikke setter cookie og bare redirecter til `/admin/login`. Admin-sesjonen settes i OIDC-callbacken (`/callback`) når signert state har admin-formål: aktiv bruker, eksakt rolle `konge`, e-post bekreftet av Google og en admin-godkjent identitet (se Identitetsmodell)
- `POST /admin/login` — magic-link-flyt for admin (samme origin kreves, anti-enumeration, 200ms floor, samme kvote som tjenestene: 3 per 15 min, formål `admin`)
- `GET /admin/verify?token=<X>` — viser bekreftelsesside (norsk, ingen e-post, ingen JavaScript). Endrer ikke tokenet
- `POST /admin/verify` — samme origin kreves. Konsumerer magic-token, sjekker konge-rolle og setter `admin_token`

### Brukeradministrasjon

- `GET /admin/users` — pagineret liste med søk på e-post og org-filter
- `GET /admin/users/new` + `POST /admin/users` — opprett bruker (valgfritt bcrypt-passord eller `n/a`)
- `GET /admin/users/{id}/edit` + `POST /admin/users/{id}` — rediger navn, roller, organisasjoner. Siden viser `public_id` og en skrivebeskyttet tabell over identiteter: leverandør, tenant (Microsoft), avkortet subject, e-post sist sett, koblet, sist brukt og om identiteten er godkjent for admin. Hver rad har en frakoblingsknapp. Siden viser også når admin-Google ble bundet, og har et eget skjema for e-postendring
- `POST /admin/users/{id}/identities/{identityID}/unlink` — koble fra en identitet (se «Frakobling»)
- `POST /admin/users/{id}/email` — endre e-post (se «E-postendring»)
- `POST /admin/users/{id}/link-invites` og `POST /admin/users/{id}/link-invites/{inviteID}/revoke` — send og trekk tilbake koblingsinvitasjon (se «Leverandøradmin og koblingsinvitasjon»). Brukersiden lister aktive invitasjoner
- `POST /admin/users/{id}/deactivate` — settes `deactivated_at = now()`
- `GET /admin/users/export` — CSV-eksport (formula-injection-beskyttet)

### Leverandører

- `GET /admin/providers` — skrivebeskyttet oversikt over generiske leverandører med lastestatus
- `POST /admin/services/{id}/providers` — tilordning per tjeneste, virker uten omstart

### Audit-logg

- `GET /admin/audit` — paginert visning, filter på e-post og service-ID
- `GET /admin/audit/export` — CSV-eksport

### Tjenestehåndtering

- `GET /admin/services` — liste alle tjenester
- `GET /admin/services/new` + `POST /admin/services` — opprett ny
- `GET /admin/services/{id}/edit` + `POST /admin/services/{id}` — full redigering inkludert fil-upload for bakgrunnsbilde, `sub_format` og `auto_link`. `sub_format` og `auto_link` auditeres i `service_created`/`service_edited`
- Cache-invalidering trigger automatisk etter mutasjon

### Bakgrunnsbilde-upload

Multipart-form med fil-validering: kun jpg/jpeg/webp/png, ≤1 MB. Filnavn genereres som `<service-id>-bg-<8 hex>.<ext>` for å unngå kollisjoner. Lagres i `static/`-katalogen og `bg_image`-feltet settes automatisk.

## Sikkerhetsmekanismer

### HMAC-signert OIDC-state

State som sendes til OIDC-providere inneholder serviceID, 128-bit nonce, utstedelsestid og eventuelt admin-formål, signert med HMAC-SHA256. Nonce er bundet til `id_token.nonce` i både Google- og Microsoft-flyten. State er gyldig i 10 minutter (+60 s klokkeskjevhet); eldre eller fremtidig state avvises. Sammenligningen ved callback bruker `hmac.Equal` (konstant-tid mot timing-angrep).

### Generiske innloggingsfeil

Feil i OIDC-flyten redirecter til `/login?error=<kode>` med en lukket mengde koder: `login_failed` (tekniske feil) og `access_denied` (ingen konto eller policybrudd, ikke til å skille utenfra). Ukjente `?error=`-verdier vises som generisk tekst i malen, aldri som gitt. Google gir også `login_failed` når utstedelsen av token feiler (tidligere `500`). Admin sendes til `/admin/login?err=ingen_tilgang`. Årsaken går til audit og logg, og flyten starter aldri leverandøren på nytt automatisk.

### Cookie-hygiene

Alle cookies har `HttpOnly: true` og `Secure: true` i prod (over Cloudflare HTTPS). `KAUTH_INSECURE_COOKIES=true` slår av Secure for lokal HTTP-utvikling. SameSite settes per kontekst:
- `auth_token` (per-service navn): `Lax`
- `refresh_token`: `None` (cross-origin SPA-støtte for `POST /token`)
- `admin_token`: `Lax`, path `/admin`
- `oidc_state` / `redirect_uri`: `Lax`

### Anti-enumeration

`POST /magic-login` og `POST /admin/login` returnerer alltid samme respons uavhengig av om e-postadressen finnes, om kvoten er brukt opp, om tjenesten har magic link av og om lagringen feilet — samme melding, samme status (200), og minst 200 ms responstid (defer-sleep om saksflyten gikk for raskt). E-post sendes asynkront, så sendetiden ikke avslører noe.

### Rate-limiting

Magic-link: 3 bestillinger per normalisert e-post og formål per 15-minutters vindu, telt i databasen (`magic_tokens`) og derfor uavhengig av restart. Det finnes ingen limit per IP ennå (BACKLOG).

### Samme origin (Sec-Fetch)

`internal/fetchmeta` avgjør om en skrivende request kommer fra kauth selv. `Sec-Fetch-Site: same-origin` godtas. Mangler headeren, må `Origin` være lik egen origin (`https://` + `Host`, `http://` bare med `KAUTH_INSECURE_COOKIES=true`). `same-site`, `cross-site`, `none`, `Origin: null` og fravær av begge gir avvisning (fail-closed). Brukes på `POST /magic-login/{token}`, `POST /admin/verify` og som middleware på alle ikke-sikre metoder under `/admin`. Avvisning gir `403`, ingen databaseskriving og ingen audit. Loggen har rutemønster og header-verdier, aldri token.

### Logout og Sec-Fetch

`/logout` er fortsatt GET, fordi klientapper navigerer dit fra egen vert. Revokering og sletting av cookies skjer bare etter denne tabellen:

| `Sec-Fetch-Site` | `Sec-Fetch-Mode` / `-Dest` | Utfall |
|---|---|---|
| mangler (eldre klient, curl) | – | Revokerer |
| `same-origin`, `same-site`, `none` | uansett | Revokerer |
| `cross-site` | `navigate` og `Dest` er `document` eller mangler | Revokerer |
| `cross-site` | alt annet (`img`/`no-cors`, `cors`, `navigate` med `iframe`) | Ingen revokering og ingen endring av cookies. Samme redirect som før |

En skjult `<img>` eller `<iframe>` på en cross-site side kan altså ikke logge brukeren ut stille. Same-site-forespørsler kan fortsatt, og synlig toppnivå-navigasjon fra en annen side revokerer. Restrisiko: `same-site` revokerer, så en kompromittert søster-app kan logge ut stille.

### E-postnormalisering

E-post normaliseres (`NormalizeEmail`: trim + små bokstaver, Unicode-bretting i Go) ved bestilling av magic link og i Google-, Microsoft-, passord- og admin-flyten, og nye brukere lagres normalisert. Oppslag på brukere er eksakt (`email = ?`) mot den normaliserte verdien, og en unik indeks (`idx_users_email_norm`) hindrer duplikater. `Ø@x.no` og `ø@x.no` finner dermed samme bruker. Kolliderer en auto-registrering med en eksisterende (f.eks. deaktivert) bruker, avvises innloggingen med `reason=user_conflict`, uten ny rad.

Migrasjon 010 har en vakt som stopper oppstart (og ruller tilbake) hvis noen `users.email` ikke er normalisert eller inneholder ikke-ASCII-tegn, i stedet for å slå sammen brukere. E-post er ikke identiteten (se Identitetsmodell).

### Audit-isolering

Vanlig audit (`Log`) går via en begrenset kø (1 024 hendelser) med én skriver-goroutine, adskilt fra auth-flyten. Hvis databasen er treig eller utilgjengelig, fortsetter auth uten å blokkere. Er køen full, droppes hendelsen. Det telles, og `audit: hendelse droppet` logges med kumulativ teller høyst hvert 10. sekund. Skriveren bruker egen kontekst med 5 s timeout per innsetting.

Admin-skrivehandlinger bruker `LogSync` (skriver direkte og returnerer feilen). `/token` og refresh bruker aldri `LogSync`.

Ved shutdown venter kauth på pågående e-postsendinger (5 s), tømmer audit-køen (`audit: tømt N hendelser`, 5 s) og lukker så databasen. Hendelser kan fortsatt gå tapt ved full kø, timeout på flush eller hard kill.

### IP-tracking via Cloudflare

`ClientIPMiddleware` ekstraherer klient-IP fra `CF-Connecting-IP` → `X-Forwarded-For` (første element) → `RemoteAddr`. Verdien legges i request-context og logges i audit-events.

### CSV-injection-beskyttelse

`csvEsc` legger til `'`-prefiks på felter som starter med `=`, `+`, `-`, `@`, `\t` eller `\r` for å nøytralisere formel-evaluering i Excel/Sheets. CSV-quoting håndteres av `encoding/csv` selv.

### Constant-time admin-rolle-sjekk

Admin-middleware verifiserer JWT, sjekker `token_use == "admin"` og `groups`-claim for `konge`, og bekrefter så mot databasen at brukeren er aktiv og har `konge` — alle kontroller før requesten slipper inn.

## Cross-host login-flyt

Brukeren går til en app (f.eks. `analyse.klarsyn.net`), blir redirected til auth-domain (`auth.klarsyn.net`). Etter vellykket login MÅ JWT komme tilbake til app-domenet — cookies funker ikke cross-host. Flyt:

1. App: `→ https://auth.<svc>/login?redirect_uri=<app-callback>`
2. Login-siden setter `redirect_uri`-cookie via JS og redirecter til valgt auth-provider
3. Provider-callback (`/callback`, `/ms-callback`, `/magic-login/{token}`, eller `POST /do-login`) utsteder JWT + refresh-token
4. Callback redirecter til `GET /dispatch?token=<jwt>&rt=<refresh>&service=<id>` (URL-param, ikke cookie)
5. Dispatcher leser tokenet, verifiserer signaturen og finner riktig tjeneste (se routing-nivåene under)
6. Redirect til app-callback med `?token=<jwt>#rt=<refresh>` — JWT som query-param, refresh-token som URL-fragment (fragmentet sendes ikke til serveren, og ikke til Referer)
7. App leser `?token=` fra URL, validerer mot JWKS

Refresh-token-cookien settes parallelt på auth-domenet med `SameSite=None` slik at `POST /token` fungerer cross-origin.

### Dispatcher-routing

`/dispatch` avgjør hvor brukeren skal lande, og prøver kildene i tur — mest presise først. Første treff vinner:

| Nivå | Kilde | Brukes av |
|------|-------|-----------|
| 1 | `redirect_uri`-cookie, sjekket mot tjenestenes allowlist | Apper som sender `?redirect_uri=` inn til `/login` |
| 2 | `?service=<id>` — service-IDen login-flyten allerede har verifisert | Alle fire login-veiene |
| 3 | Host-header mot `services.auth_host` | Tjenester med eget auth-domene |
| 4 | `org`-claim mot `services.default_org` | Bakoverkompatibilitet |
| 5 | Default-tjenestens `callback_url` | Siste utvei |

**Nivå 0 (OIDC `authorization_code`).** Med `oidc_authz`-cookie lager `/dispatch` en kode bare hvis tokenets `aud` inneholder `client_id` og tokenet er ferskt: `iat` høyst 120 s gammelt, med 30 s slingring for `iat` i framtiden. Manglende `iat` eller `aud` avvises. Ved avvik går brukeren til `/login`, ingen kode lages, og audit logger `dispatch_aud_mismatch` (`level=0`) eller `dispatch_token_stale`. Ferskhetskravet begrenser hva et lekket eller gammelt token kan brukes til via `/dispatch?token=`. Tokenets `sub` må tilhøre brukeren: for `sub_format=id`-tjenester slås brukeren opp på `public_id` og normalisert `email`-claim må stemme, for `email`-tjenester på normalisert e-post. Avvik gir `/login` og audit `dispatch_subject_mismatch`. Koden lagres med `user_id`.

**Nivå 1–5: brukersjekk før rutingen (013).** Før noe nivå velger mål, slår `/dispatch` opp den aktive brukeren med normalisert `email`-claim. Tokenet sendes bare videre når brukeren finnes, `sub` er brukerens e-post eller `public_id`, og `iat` finnes og ikke er eldre enn e-postepoken. Ellers går brukeren til `/login`, og audit logger `dispatch_subject_mismatch` med `level=1-5 reason=no_active_user|sub_mismatch|iat_missing|email_reassigned`. `sub` godtas i begge former fordi målet på nivå 1–5 ikke alltid er tokenets `aud`.

En DB-feil i oppslaget stopper ikke innloggingen: tokenet sendes videre, og audit logger `dispatch_subject_check_skipped` (`level=1-5 reason=db_error`). En klient som har koblet fra, logges ikke. Et token som er eldre enn 120 s, eller mer enn 30 s fram i tid, sendes videre, men logges som `dispatch_token_stale` med `level=1-5 age_s=<n> mode=audit`. Mangler `iat` etter fail-open, står det `iat=missing mode=audit`. Auditen skal vise om ferskhet bør håndheves også her (se BACKLOG).

**`aud` på nivå 1–5 auditeres, men avvises ikke.** Er målet verken i tokenets `aud` eller deler callback med `aud`-tjenesten (klarsyn og analyse), logges `dispatch_aud_mismatch` med `level=N`, `token_aud` og `target`. Rutingen er uendret. Auditen skal vise om noen klient trenger avvisning før den slås på (se BACKLOG).

Nivå 2 er den pålitelige: for Google og Microsoft kommer IDen fra den HMAC-signerte state-parameteren (`SignState`/`VerifyState`), som round-trippes gjennom provideren og ikke kan forfalskes. Magic-link og passord sender den resolvet tjenesten direkte.

IDen valideres alltid mot registryet, og redirect går kun til `callback_url` slik den står i databasen — aldri til en URL fra requesten. En ukjent eller påfunnet `?service=` kan derfor ikke styre hvor brukeren havner; den faller bare gjennom til neste nivå.

Nivå 4 er en heuristikk og bør ikke stoles på: den itererer over tjenestene i `display_name`-rekkefølge og tar den første med en `default_org` brukeren har. En bruker som ikke har tjenestens `default_org` blant sine orgs vil havne feil. Den står igjen kun for forespørsler uten `?service=`, og bør fjernes når ingenting eksternt bruker den (se `CHANGELOG.md`, Unreleased/Fixed).

### Admin Google-flyten og `/dispatch`

Intern-sti-grenen i `/dispatch` er fjernet: på nivå 1 godtas bare en `redirect_uri` som er eksakt lik en registrert `callback_url`. Admin Google-flyten går ikke lenger via `/dispatch`. `/admin/google-init` legger admin-formål i den signerte state-parameteren, og `/callback` setter `admin_token`-cookien direkte (ingen JWT i URL-en) og redirecter til `/admin/users`. Peker nivå 1 til en callback hos en annen tjeneste enn den verifiserte, logges `redirect_service_mismatch` (007 F9).

## Audit-logg

Lagret i `audit_events`-tabellen med felter:
- `event_type` — `login_success`, `login_failed`, `magic_link_login`, `google_oidc_login`, `microsoft_oidc_login`, `google_oidc_rejected`, `microsoft_oidc_rejected`, `oidc_login`, `oidc_rejected`, `admin_login`, `admin_logout`, `admin_google_login`, `refresh_token_issued`, `refresh_token_rotated`, `refresh_token_reuse`, `refresh_token_revoked_presented`, `dispatch_aud_mismatch`, `dispatch_token_stale`, `dispatch_subject_mismatch`, `dispatch_subject_check_skipped`, `user_logout`, `user_deactivated`, `service_created`, `service_edited`, `service_providers_updated`, `identity_link_invited`, `identity_link_invite_revoked`, `identity_linked`, `identity_link_rejected`, ...
- `auth_method` — `google`, `microsoft`, `oidc`, `magic_link`, `password`, `refresh`
- `email`, `service_id`, `ip_address`, `user_agent`
- `success` — bool, alltid eksplisitt satt av applikasjonen
- `details` — fritekst, brukes for grunn på feilet login. `microsoft_oidc_rejected` har `reason=code_exchange` og `reason=id_token` i tillegg til de øvrige årsakene. `refresh_token_reuse` har `gap_s=<n>`, `user_deactivated` har `id=<n> revoked=<antall>` eller `id=<n> revoke_failed` (deaktiveringen står selv om revokeringen feiler; refresh for deaktivert bruker avvises uansett)
- `created_at` — ISO 8601 UTC

Nye event-typer fra 009: `authorization_code_invalid`, `authorization_code_mismatch`, `authorization_code_reuse`, `authorization_code_exchanged`. Fra 010: `authorization_code_exchanged` har `jti_access`, `jti_id` og `family` i `details`, og `authorization_code_reuse` har `family`. `dispatch_aud_mismatch` har `level=<0-5>`, `token_aud` og `target`, og `dispatch_token_stale` har `age_s=<n>`, eller `iat=missing` når `iat` mangler. Fra 013 har nivå 1–5 `level=1-5` og `mode=audit` på `dispatch_token_stale` (success=1, tokenet sendes videre), `dispatch_subject_mismatch` har `level=1-5 reason=…`, og `dispatch_subject_check_skipped` (success=1) markerer fail-open ved DB-feil. Ingen av dem har token eller kode i `details`. Admin-skriv har `actor=<e-post>` i `details`. Skrivingen er asynkron via kø, bortsett fra admin-skriv (se Audit-isolering).

90 dagers retensjon (cleanup-jobb sletter eldre). Eksporteres via admin GUI som CSV.

## Bakgrunnsjobber

Goroutiner med 1 times tick, kjører umiddelbart ved oppstart:

- **`cleanMagicTokens`** — sletter brukte magic-tokens som er utløpt, og ubrukte som er eldre enn 24 timer
- **`cleanRefreshTokens`** — sletter refresh-tokens der `expires_at` er passert OG `family_expires_at` enten er null eller passert
- **`cleanAuditEvents`** — sletter audit-events eldre enn 90 dager
- **Koblingsinvitasjoner** — sletter rader i `identity_link_invites` som utløp for mer enn 7 døgn siden (brukte og ubrukte)

Alle stopper rent på `ctx.Done()` ved SIGTERM/SIGINT.

## Endepunkter

### Offentlige

`/login` og `/magic-login` støtter begge `?lang=<nb|en|de>` for å velge visningsspråk. Parameteren overstyrer `Accept-Language`-headeren; en ukjent verdi faller tilbake til `Accept-Language` i stedet for å tvinge engelsk, og total fallback (ingen match noe sted) er engelsk. Nyttig for en relying party som vet at brukeren foretrekker et gitt språk — f.eks. `?lang=de` på redirect til login.

| Metode | Sti | Beskrivelse |
|---|---|---|
| GET | `/login` | Login-side, valgfri `?service=<id>`, `?redirect_uri=<url>` og `?lang=<nb\|en\|de>` — fungerer også som `authorization_endpoint` for standard OIDC (`?response_type=code&client_id=...&code_challenge=...`) |
| GET | `/login.html`, `/login-pov.html` | Legacy 301 → `/login` |
| GET | `/oidc-login`, `/social-login` | Initier Google OAuth |
| GET | `/callback` | Google OAuth callback |
| GET | `/ms-oidc-login`, `/ms-social-login` | Initier Microsoft OAuth |
| GET | `/ms-callback` | Microsoft OAuth callback |
| GET | `/idp/{slug}/login` | Initier innlogging mot generisk OIDC-leverandør (`?service=<id>`) |
| GET | `/idp/{slug}/callback` | Callback fra generisk OIDC-leverandør |
| GET | `/link/{token}` | Bekreftelsesside for koblingsinvitasjon (endrer ingenting) |
| POST | `/link/{token}` | Start kobling hos leverandøren (samme origin kreves) |
| GET | `/magic-login` | Magic-link-skjema, valgfri `?service=<id>` og `?lang=<nb\|en\|de>` |
| POST | `/magic-login` | Send magic-link |
| GET | `/magic-login/{token}` | Bekreftelsesside (endrer ingenting) |
| POST | `/magic-login/{token}` | Konsumer magic-token (samme origin kreves) |
| POST | `/do-login` | Passord-login (hvis aktivert) |
| POST | `/token` | `grant_type=refresh_token` eller `grant_type=authorization_code` (+ PKCE) — CORS-aktivert |
| GET | `/dispatch` | Post-login dispatcher |
| GET | `/logout` | Revokerer refresh-familien, sletter cookies, redirect (se tabellen under Sikkerhetsmekanismer) |
| GET | `/api/me` | JWT-introspection (returnerer claims som JSON) |
| GET | `/.well-known/jwks.json` | JWKS — CORS-aktivert |
| GET | `/.well-known/openid-configuration` | Discovery — CORS-aktivert |
| GET | `/static/*` | Statiske filer |

### Admin

| Metode | Sti | Beskyttelse |
|---|---|---|
| GET | `/admin/login` | Åpen |
| POST | `/admin/login` | Åpen — samme origin, anti-enumeration |
| GET | `/admin/verify` | Åpen — bekreftelsesside, krever magic-token |
| POST | `/admin/verify` | Åpen — samme origin, konsumerer magic-token |
| GET | `/admin/logout` | Åpen |
| GET | `/admin/google-init` | Åpen — starter Google-flyt med admin-formål i signert state |
| GET | `/admin/google-callback` | Åpen — utgått, redirecter til `/admin/login` uten å sette cookie |
| GET | `/admin/users[/new/{id}/edit/export]` | konge-rolle |
| POST | `/admin/users[/{id}[/deactivate]]` | konge-rolle, samme origin |
| GET | `/admin/audit[/export]` | konge-rolle |
| GET, POST | `/admin/services[/new/{id}/edit]` | konge-rolle, POST med samme origin |
| POST | `/admin/services/{id}/providers` | konge-rolle, samme origin |
| GET | `/admin/providers` | konge-rolle |
| POST | `/admin/users/{id}/link-invites[/{inviteID}/revoke]` | konge-rolle, samme origin |

## Datamodell

Ni SQLite-tabeller med WAL og foreign keys på:

### `services`

Tjeneste-konfigurasjon. 30+ kolonner inkludert id, sub_format, auto_link, display_name, domain, auth_host, callback_url, branding (theme, accent_color, logo_html, bg_image, bg_css), auth-flagg (auth_google/microsoft/magic_link/password), OAuth-creds (per-service), TTL-er, default_role/org, is_default, active, updated_at. `id` er også `client_id` for en tjeneste som bruker OIDC `authorization_code`-flyten — ingen egen klient-tabell.

### `users`

Brukerkontoer: id, public_id (UUID v4, unik, uforanderlig), email (unik på `lower(trim(email))`), password_hash, name, roles (CSV), orgs (CSV), created_at, last_login, deactivated_at.

### `user_identities`

Eksterne identiteter: id, user_id (FK til `users`, `ON DELETE CASCADE`), provider (`google`/`microsoft`/`oidc`), issuer, subject, email (sist sett), admin_ok, created_at, last_used_at. Unik på `(issuer, subject)`.

### `identity_providers` og `service_identity_providers`

Generiske OIDC-leverandører (015): id, slug (unik), display_name, issuer (unik), client_id, client_secret_env (navnet på en `KAUTH_IDP_*`-variabel, aldri selve hemmeligheten), scopes, trust_email, email_domains, active, created_at. Tilordningen har `(service_id, provider_id)` som primærnøkkel og `position`, og slettes med tjenesten eller leverandøren. CHECK-regler i databasen speiler lastereglene som forsvar i dybden. Se [IDENTITY_PROVIDERS.md](IDENTITY_PROVIDERS.md).

### `identity_link_invites`

Koblingsinvitasjoner (016): id, token_hash (SHA-256 hex, unik), user_id, provider_id, service_id (alle med `ON DELETE CASCADE`), email (brukerens e-post da invitasjonen ble laget), created_by, created_at, expires_at, used_at (satt ved kobling, tilbaketrekking eller erstatning). Tidsstempler skrives i fast format `%Y-%m-%dT%H:%M:%SZ` fordi de sammenlignes som tekst.

### `magic_tokens`

Engangs-innloggingstokens: id, token (SHA-256-hex), email (normalisert), service_id (NULL for admin), purpose (`service`/`admin`), redirect_uri, created_at, expires_at, used.

### `refresh_tokens`

Opake refresh-tokens med family-tracking: id, token_hash (sha256 hex, CHECK length=64), email, user_id (nullable, FK til `users`), service_id, family_id, parent_id, created_at, expires_at, family_expires_at, used, revoked, revoked_reason, ip_address, user_agent.

### `audit_events`

Hendelseslogg: id, event_type, auth_method, email, service_id, ip_address, user_agent, success, details, created_at.

### `authorization_codes`

Engangs-autorisasjonskoder for OIDC `authorization_code`-flyten: id, code (SHA-256-hex), family_id (settes ved innløsning), service_id, email, user_id (nullable, FK til `users`), redirect_uri, scope, nonce, code_challenge, code_challenge_method, created_at, expires_at, used.

## Drift og kjøremiljø

- **Single static binær** — ingen CGO, ingen runtime-avhengigheter (modernc.org/sqlite)
- **Cross-compile** — `make build-arm64` for ARM64-linux
- **Graceful shutdown** — `signal.NotifyContext` + `srv.Shutdown(15s)`, så pågående e-postsendinger (5 s), `auditSvc.Close` (5 s) og til slutt `sqlDB.Close()`. Cleanup-goroutiner stopper rent på `ctx.Done()`
- **Minne** — `GOMEMLIMIT=96MiB` + cgroup `MemoryHigh=112M` / `MemoryMax=128M` via systemd
- **Strukturerte logger** — `log/slog`, JSON-format, til journald via systemd
- **WAL-modus** — SQLite med `journal_mode=WAL` og `foreign_keys=ON` ved oppstart
- **Daglig backup** — `scripts/backup-kauth-go.sh` via cron 03:00, `sqlite3 .backup` for atomisk konsistent kopi (trygt mens kauth kjører), 30 dagers retensjon
- **Cloudflare Tunnel** — TLS-terminering og DDoS-beskyttelse, klient-IP via `CF-Connecting-IP`
- **systemd-tjeneste** — kjører som `lars`, `ProtectSystem=strict`, `NoNewPrivileges`, `Restart=on-failure`
