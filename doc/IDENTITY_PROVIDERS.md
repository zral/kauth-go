# Generiske OIDC-leverandører — driftsprosedyre

Slik legger du en ekstern OIDC-leverandør (Authentik, Keycloak, Entra-tenant med egen app, en kommunal IdP) til i kauth, og slik feilsøker og fjerner du den. Dokumentet skal kunne følges uten å lese koden. Bakgrunn og avveininger står i ADN 17 ([ARCHITECTURE_DESIGN_NOTES.md](ARCHITECTURE_DESIGN_NOTES.md)). Funksjonsbeskrivelsen står i [FEATURES.md](FEATURES.md#generisk-oidc).

Google og Microsoft ligger utenfor dette. De har egne flyter og egne kolonner i `services`, og kan ikke registreres som generisk leverandør.

## Hva en generisk leverandør er

En rad i `identity_providers`, tilordnet én eller flere tjenester i `service_identity_providers`. Brukeren starter på `/login?service=<id>`. Tjenester med tilordning får en ekstra knapp der («Fortsett med <navn>») som peker på `/idp/<slug>/login?service=<id>`. Tilbakeruten er `GET /idp/<slug>/callback`. Etter vellykket innlogging går brukeren gjennom samme utstedelse og `/dispatch` som ved Google og Microsoft.

En rad er en tillitserklæring på linje med en signeringsnøkkel. Derfor er det fire forsvarslinjer:

1. **To nøkler.** Raden lastes bare når issueren også står eksakt i `KAUTH_OIDC_ISSUERS`. Noen som bare kan skrive til databasen, kan ikke åpne en ny utgiver.
2. **Låst utgående klient.** All trafikk mot leverandøren (discovery, JWKS, token-endepunkt) går via én HTTP-klient: bare https, ingen redirect, 10 s tidsavbrudd, 1 MiB svartak, og avvisning av loopback, private, link-local og andre ikke-offentlige adresser.
3. **E-post uten tillit som standard.** Med `trust_email=0` logger bare allerede koblede identiteter inn. Ingen kobling til eksisterende bruker og ingen registrering på en e-postadresse leverandøren sier at den eier.
4. **Hemmeligheten ligger i miljøet.** Raden har bare navnet på miljøvariabelen, og navnet må starte med `KAUTH_IDP_`. En rad kan derfor ikke peke på `KAUTH_PRIVATE_KEY_PEM` eller andre interne hemmeligheter.

I tillegg gir en generisk identitet aldri admin-tilgang (`admin_ok` er alltid 0 for `provider='oidc'`, og admin-innloggingen har ingen vei inn via `/idp`).

## Forutsetninger hos leverandøren

Registrer kauth som klient hos leverandøren før du rører kauth:

- **Redirect URI:** `https://<vert>/idp/<slug>/callback`, én per tjenestevert. kauth bygger den fra verten brukeren nådde kauth på, normalt `auth_host` på hver tjeneste som skal ha leverandøren (`http` bare med `KAUTH_INSECURE_COOKIES=true`). Har tre tjenester tre verter, registrerer du tre URI-er. `<slug>` er den du velger under.
- **Scopes:** `openid` er påkrevd. Standarden er `openid email profile`. Trenger du e-post, må `email` være med.
- **Flyt:** authorization code med PKCE. kauth sender alltid `code_challenge_method=S256`, også for konfidensiell klient. Leverandøren må godta det.
- **Klientautentisering:** `client_secret_basic` eller `client_secret_post`. kauth leser `token_endpoint_auth_methods_supported` fra discovery og foretrekker basic. Annonserer leverandøren ingen metoder, brukes basic. Annonserer den bare andre metoder (for eksempel `private_key_jwt`), feiler discovery med `auth_method`. Uten hemmelighet (`client_secret_env` er NULL) behandles klienten som offentlig: bare `client_id` i kroppen, og PKCE er beskyttelsen.
- **id_token må signeres med RS256/384/512, PS256/384/512, ES256/384/512 eller EdDSA.** HS256 og `none` godtas aldri. kauth bruker snittet av det leverandøren annonserer i `id_token_signing_alg_values_supported` og denne listen. Annonserer den ingenting, gjelder RS256 (OIDC Discovery §3). Er snittet tomt, feiler discovery med `no_algs`.
- **Discovery:** `https://<issuer>/.well-known/openid-configuration` må være nåbar fra Pi-en. `issuer` i dokumentet må være lik issuer-strengen byte for byte. `authorization_endpoint`, `token_endpoint` og `jwks_uri` må være https.
- **Valgfritt men anbefalt:** `authorization_response_iss_parameter_supported: true` (RFC 9207). Annonserer leverandøren det, krever kauth `iss` i svaret.
- `sub` er maks 255 tegn. Har `aud` flere verdier, må `azp` finnes og være lik `client_id`. En `azp` som er satt, må alltid være lik `client_id`.

## Legge til en leverandør

**SQL mot databasen.** Alle `sqlite3`-blokkene under kjøres mot `/home/lars/kauth-go/data/kauth.db`, og du tar backup først (`sqlite3 /home/lars/kauth-go/data/kauth.db ".backup /home/lars/backups/kauth-go/kauth-<tidspunkt>.db"`). Start hver økt med `PRAGMA foreign_keys = ON;`. `sqlite3`-kommandolinjen har fremmednøkler av som standard, og da følger ikke `ON DELETE CASCADE` med: en `DELETE` av en leverandør eller tjeneste etterlater tilordningene. `identity_providers.id` bruker `AUTOINCREMENT` og gjenbrukes aldri, så en foreldreløs tilordning kan ikke bli arvet av neste leverandør. Den ligger harmløst igjen, men gir ingen advarsel. Finn den med SQL-en under «Sjekke at den er lastet».

kauth krever allerede `KAUTH_OIDC_STATE_SECRET` for all innlogging, og den brukes også her (state og PKCE). Du trenger ikke sette noe nytt for den.

Endringer i tabellene og miljøet leses bare ved oppstart. Du må restarte (se under).

### 1. Hemmeligheten

Legg den i `/home/lars/kauth-go/.env`, som systemd-enheten `kauth` leser via `EnvironmentFile`. Navnet må matche `^KAUTH_IDP_[A-Z0-9_]+$`:

```
KAUTH_IDP_ACME=<client secret fra leverandøren>
```

Verdien brukes ordrett, uten trimming. En tom verdi eller bare mellomrom gir `secret_env_empty`. Hopp over steget for offentlig klient og sett `client_secret_env` til NULL.

### 2. Issuer i allowlisten

Legg issueren i `KAUTH_OIDC_ISSUERS`, mellomrom- eller komma-separert, med nøyaktig samme streng som i raden og som `issuer` i discovery-dokumentet:

```
KAUTH_OIDC_ISSUERS=https://login.acme.example https://sso.annen.example
```

Strengene sammenlignes byte for byte. En avsluttende `/`, store bokstaver eller en port som bare står ett av stedene, gir `issuer_not_allowlisted`. `@` eller brukerinfo i URL-en gir `issuer_invalid`. Har leverandøren `https://login.acme.example/realms/main` som issuer, er det hele den strengen som skal stå begge steder.

### 3. Raden

```sql
PRAGMA foreign_keys = ON;
INSERT INTO identity_providers
  (slug, display_name, issuer, client_id, client_secret_env, scopes, trust_email, email_domains, active)
VALUES
  ('acme', 'Acme', 'https://login.acme.example', 'kauth-prod', 'KAUTH_IDP_ACME',
   'openid email profile', 0, '', 1);
```

Kolonner og regler (databasen håndhever de fleste med `CHECK`, og koden validerer alt på nytt ved lasting):

| Kolonne | Regel |
|---|---|
| `slug` | Unik. 1–32 tegn av `a-z`, `0-9` og `-`. Brukes i URL-en `/idp/<slug>/...` og kan ikke endres uten å endre redirect-URI-ene hos leverandøren |
| `display_name` | Vises på knappen. Ikke tom, maks 64 tegn. HTML escapes |
| `issuer` | Unik, `https://` med vert, uten brukerinfo, query eller fragment. Må stå eksakt i `KAUTH_OIDC_ISSUERS`. Kan ikke være Google eller Microsoft. Koden avviser seks verter: `accounts.google.com`, `login.microsoftonline.com`, `sts.windows.net`, `login.windows.net`, `login.microsoft.com` og `login.live.com`. `CHECK` i databasen dekker bare Google, `login.microsoftonline.com`, `sts.windows.net` og `login.live.com` |
| `client_id` | Fra leverandøren |
| `client_secret_env` | NULL (offentlig klient), eller et navn som starter med `KAUTH_IDP_`, bare `A-Z`, `0-9` og `_`. Variabelen må finnes og ikke være tom |
| `scopes` | Mellomromseparert. Må inneholde `openid`. Standard `openid email profile` |
| `trust_email` | `0` (standard) eller `1`. Se under |
| `email_domains` | Kommaseparert, små bokstaver, for eksempel `acme.example,acme.no`. Hvert domene må være et gyldig vertsnavn (ingen `@`, port, sti eller wildcard). Påkrevd når `trust_email=1` |
| `active` | `1` eller `0`. Bare `1` lastes |

### 4. Tilordne til tjeneste

```sql
PRAGMA foreign_keys = ON;
INSERT INTO service_identity_providers (service_id, provider_id, position)
SELECT 'polaris', id, 0 FROM identity_providers WHERE slug = 'acme';
```

`service_id` er `services.id`. `position` styrer rekkefølgen på knappene (lavest først, så slug). Tjenesten trenger ikke noe eget flagg. Uten tilordning vises ingen knapp, og `/idp/<slug>/login?service=<id>` gir `login_failed`.

### 5. Restart

```bash
sudo systemctl restart kauth
```

## Sjekke at den er lastet

```bash
journalctl -u kauth -n 100 | grep 'idp:'
```

- `idp: N generiske OIDC-leverandører lastet` er tallet som passerte validering. Forventet N er antall aktive rader du har lagt inn. Rader med `active=0` leses ikke i det hele tatt: de lastes ikke, og de logges ikke. Tellelinjen er eneste spor.
- Hver avvist rad gir `idp: leverandør ikke lastet slug=<slug> reason=<kode>`. Oppstarten feiler ikke av dette, siden én feil rad ikke skal ta ned de andre tjenestene.
- `idp: tilordning til leverandør som ikke er lastet service=<id> provider_id=<n>` betyr at en tjeneste er tilordnet en rad som er aktiv, men ble avvist ved validering. Tjenesten viser ingen knapp for den. Slettede eller inaktive leverandører gir ingen slik linje. Foreldreløse tilordninger (til slettede leverandører) finner og fjerner du slik:

```sql
PRAGMA foreign_keys = ON;
SELECT service_id, provider_id FROM service_identity_providers
WHERE provider_id NOT IN (SELECT id FROM identity_providers);
DELETE FROM service_identity_providers
WHERE provider_id NOT IN (SELECT id FROM identity_providers);
```

Koder ved avvisning ved lasting:

| `reason` | Betydning |
|---|---|
| `bad_slug` | Slug matcher ikke `^[a-z0-9-]{1,32}$` |
| `display_name_empty` | `display_name` er tom eller bare mellomrom |
| `display_name_too_long` | Mer enn 64 tegn |
| `issuer_not_allowlisted` | Issueren står ikke eksakt i `KAUTH_OIDC_ISSUERS` |
| `issuer_reserved` | Google- eller Microsoft-vert |
| `issuer_invalid` | Ikke https med vert, eller har brukerinfo, query eller fragment (http godtas bare med `KAUTH_OIDC_ALLOW_INSECURE`) |
| `secret_env_name` | `client_secret_env` matcher ikke `KAUTH_IDP_[A-Z0-9_]+` |
| `secret_env_empty` | Variabelen er ikke satt, tom eller bare mellomrom |
| `scope_openid_missing` | `scopes` mangler `openid` |
| `bad_email_domain` | Et domene i `email_domains` er ugyldig |
| `trust_email_without_domains` | `trust_email=1` uten domener |

Sjekk også at discovery virker ved første innlogging. Discovery hentes lat (ved første forsøk) og caches i 24 timer. En leverandør som er lastet, men ikke nåbar, gir `idp: discovery feilet slug=<slug> reason=<kode>` og `oidc: discovery feilet`:

| Discovery-`reason` | Betydning |
|---|---|
| `timeout` | Ingen svar innen 10 s |
| `too_large` | Svar over 1 MiB |
| `redirect` | Leverandøren svarte med redirect (følges aldri) |
| `blocked_address` | Verten peker på en ikke-offentlig adresse |
| `endpoint_scheme` | Et endepunkt i discovery-dokumentet er ikke https |
| `issuer_mismatch` | `issuer` i dokumentet er ulik issuer i raden |
| `http_status` | Annen HTTP-feilkode enn 200 |
| `no_algs` | Ingen tillatte signaturalgoritmer |
| `auth_method` | Leverandøren annonserer ingen klientautentisering kauth støtter |
| `fetch` | Annen feil (nettverk, ugyldig JSON, ...) |

Cachen er stale-while-revalidate: etter 24 timer brukes forrige verdi straks og fornyes i bakgrunnen, og en gammel verdi gjelder i opptil 7 døgn hvis fornyelsen feiler. Feiler første henting, venter kauth 60 s før neste forsøk.

## Teste

Etter restart, fra en maskin som når kauth. Cookie-jar trengs fordi state ligger i `idp_state`-cookien:

```bash
curl -si -c jar.txt 'https://<auth_host>/idp/<slug>/login?service=<id>' | grep -i '^location'
```

Svaret er `302` til leverandørens `authorization_endpoint` med `code_challenge_method=S256`, `state`, `nonce` og `redirect_uri=https://<auth_host>/idp/<slug>/callback`. Åpne `Location` i nettleseren, logg inn hos leverandøren og følg redirecten tilbake. Med curl kan du følge den til leverandøren selv hvis den godtar innlogging uten nettleser, og så sende det du får tilbake til callback-URL-en med samme `-b jar.txt`. Landingen er `/dispatch` med token ved suksess, eller `/login?error=...` ved avvisning. Se så etter `oidc_login` eller `oidc_rejected` i audit.

## Tillit til e-post: `trust_email`

### `trust_email=0` (standard)

Bare identiteter som allerede er koblet til en bruker, kan logge inn. En ukjent identitet avvises med `access_denied` uansett hva e-posten er, og uansett `auto_link` og `auto_register` på tjenesten. Det gjøres ingen kobling og ingen registrering.

Brukeren ser `access_denied` på login-siden. Admin ser `oidc_rejected` med `reason=email_untrusted` i audit. Bruk dette for en leverandør du ikke styrer, eller når du vil koble hver konto for hånd.

### `trust_email=1`

Krever minst ett domene i `email_domains`. Da gis tillit til e-posten, og kobling (`auto_link`) og registrering (`auto_register`) følger tjenestens vanlige regler, bare når alt dette holder:

- id_token har `email_verified` lik `true` (boolsk eller strengen `"true"`). Manglende eller `false` gir ingen tillit.
- E-posten er ren ASCII: bare tegn fra `0x21` til `0x7e`, nøyaktig én `@`, gyldig form. Mellomrom (også i endene), kontrolltegn og alle unicode-tegn gir ingen tillit. Grunnen er at kauths e-postnormalisering bretter unicode (for eksempel Kelvin-tegnet U+212A til `k`), slik at en betrodd IdP kunne latt en adresse med Kelvin-tegnet foran «ari» treffe `kari@firma.no`. Gjelder også NBSP i enden.
- Domenet (delen etter siste `@`) er lik et domene i `email_domains`. Subdomener teller ikke: `acme.example` dekker ikke `mail.acme.example`.
- E-posten finnes. Mangler den helt mens `trust_email=1`, avvises **alle** innlogginger fra leverandøren med `reason=email_missing`, også for allerede koblede identiteter, fordi sjekken kommer før oppslaget.

Mangler ett av de tre første vilkårene, behandles innloggingen som `trust_email=0`: kjent identitet slipper inn, ukjent avvises med `email_untrusted`.

Sjekk tjenestens regler før du slår på tillit: `SELECT auto_register, auto_link FROM services WHERE id='<id>';`. Med `auto_link=1` kobles en ukjent identitet til brukeren med samme e-post. Med `auto_register=1` opprettes en ny bruker når ingen finnes. Med `auto_link=0` kobles likevel brukerens første føderte identitet, altså en bruker som ikke har noen identitet fra før (overgangsunntaket, ADN 13). Etter det gjelder `account_not_linked`.

Sett `trust_email=1` bare når leverandøren verifiserer e-post og eier domenene (en bedrifts egen IdP). En åpen IdP med `trust_email=1` er kontoovertakelse: hvem som helst kan melde seg inn med en adresse på domenet hvis leverandøren ikke verifiserer den.

Hva brukerne opplever: med `trust_email=1` kobler eller registrerer første innlogging dem uten ekstra steg. Med `trust_email=0` får en ukjent bruker `access_denied` på login-siden til admin har koblet kontoen.

## Manuell kobling ved `trust_email=0`

Admin kobler en konto til en eksisterende bruker med `user_identities`. Du trenger tre ting:

1. `user_id`: `SELECT id, email FROM users WHERE email = 'kari@acme.example';`
2. `issuer`: eksakt som i `identity_providers.issuer`.
3. `subject`: `sub` fra leverandøren for denne personen.

**Hvor finner du `sub`?** Ikke i kauth. `oidc_rejected` med `reason=email_untrusted` inneholder e-postadressen (normalisert) og `provider=<slug>`, men ikke `sub`. Heller ikke andre audit-rader eller logger har `sub` (bevisst, ADN 17). Be brukeren logge inn én gang (det gir en avvisning, men ingen `sub` hos oss), og hent `sub` hos leverandøren. Se brukerens profil eller bruker-ID i leverandørens admin-grensesnitt, eller `sub` i et id_token som leverandørens egen testside eller verktøy viser. Verdien må være identisk med det leverandøren sender som `sub` til kauth, byte for byte. Er du i tvil om det er rett verdi, test: etter koblingen skal personen komme inn, ellers er `sub` feil (da gir innloggingen fortsatt `email_untrusted`).

```sql
INSERT INTO user_identities (user_id, provider, issuer, subject, email)
VALUES (42, 'oidc', 'https://login.acme.example', '<sub fra leverandøren>', 'kari@acme.example');
```

`provider` må være `'oidc'`. `(issuer, subject)` er unik: finnes den fra før, får du en feil, og identiteten tilhører da en annen bruker. `admin_ok` skal ikke settes (databasen avviser `1` for `oidc`). Etter koblingen trenger du ikke restart. Neste innlogging slår opp identiteten først.

`sub` er stabilt for én leverandør, men to leverandører kan sende samme `sub` til ulike personer. Identiteten er derfor `(issuer, subject)`, ikke `subject` alene.

Admin-siden for en bruker viser identitetene, men bare som «oidc» med forkortet subject, ikke leverandørnavnet (BACKLOG). Kjenner du issueren, finner du leverandøren slik:

```sql
SELECT u.email, i.issuer, i.subject, i.last_used_at
FROM user_identities i JOIN users u ON u.id = i.user_id
WHERE i.provider = 'oidc';
```

## Feilsøking via audit

Suksess er `oidc_login` med `auth_method=oidc`. De fleste avvisninger er `oidc_rejected` med `Details` på formen `provider=<slug> reason=<kode>`. Unntakene står under tabellen. Brukeren ser bare en generisk feil (`login_failed`, `access_denied` eller `account_not_linked`), aldri teksten fra leverandøren.

| `reason` | Årsak og tiltak |
|---|---|
| `unknown_service` | Staten er gyldig og signert, men tjenesten i den finnes ikke eller er inaktiv (Details har `provider=`). Ugyldig eller utløpt state gir ikke denne |
| `unknown_provider` | Slug i stien er ulik slug i staten, eller leverandøren er ikke (lenger) tilordnet tjenesten eller ikke lastet. Sjekk tilordning og startloggen |
| `provider_error` | Leverandøren sendte `error=` i tilbakeruten (bruker avbrøt, eller klienten er feilkonfigurert hos dem). Se leverandørens egen logg |
| `issuer_param` | `iss`-parameteren er ulik issuer i raden, eller leverandøren annonserer RFC 9207 men sendte ingen, eller metadata kunne ikke leses |
| `discovery` | Discovery feilet. Se `idp: discovery feilet ... reason=` i journalen (tabellen over) |
| `code_exchange` | Token-endepunktet avviste koden. Vanligst: feil `client_secret`, redirect-URI som ikke er registrert hos leverandøren, eller at leverandøren krever noe annet enn PKCE S256. Feilteksten logges ikke |
| `id_token_missing` | Token-svaret hadde ikke `id_token` (mangler `openid` i scopes hos leverandøren?) |
| `id_token` | Signatur, `iss`, `aud`, utløp eller `azp` er ugyldig. Sjekk `client_id`, at leverandøren signerer med en tillatt algoritme, og klokkene |
| `nonce` | Nonce i id_token er ulik den kauth sendte |
| `missing_sub` | `sub` mangler, er tomt eller lengre enn 255 tegn |
| `email_missing` | `trust_email=1`, men id_token har ingen e-post. Sjekk at `email` er med i `scopes` |
| `email_untrusted` | Ukjent identitet uten tillit til e-posten: `trust_email=0`, `email_verified` ikke sann, e-post med unicode eller mellomrom, eller domene utenfor `email_domains`. Raden har e-posten (normalisert), men ikke `sub`. Manuell kobling over løser det for `trust_email=0` |
| `user_inactive` | Brukeren er deaktivert. Details har bare `reason=`, ikke `provider=` |
| `user_conflict` | Auto-registrering kolliderte med en eksisterende rad. Details har bare `reason=` |
| `internal` | Intern feil (skal ikke forekomme i drift). Details har bare `reason=`. Meld fra |

Disse gir **ingen** `oidc_rejected`, bare en redirect til login-siden (og eventuelt en linje i journalen):

- Ugyldig, utløpt eller manglende state, eller `idp_state`-cookie som ikke er lik `state` i URL-en, og state som hører til Google, Microsoft eller admin.
- Ukjent eller ikke-tilordnet slug ved `/idp/<slug>/login` (en feil lenke, `login_failed`). Ved callback gir derimot en fjernet tilordning `unknown_provider`.
- Policyavslag fra `checkPolicy` (for eksempel `require_role`): `access_denied`.
- `auto_link=0` som stopper en kobling: `account_not_linked`. Det gir `identity_link_denied` (under), ikke `oidc_rejected`.
- Ukjente DB-feil ved oppslag eller opprettelse av bruker: `login_failed`, bare logget.
- Betrodd e-post, men ingen bruker og `auto_register=0`: `access_denied`.

Utenom `oidc_rejected`: `identity_linked` (med `provider=oidc issuer=...`) når en identitet kobles til en eksisterende bruker, `identity_link_denied` når `auto_link=0` stopper en kobling, og `identity_email_mismatch` når en koblet identitet kommer med en annen e-post enn brukerens. Ny bruker via auto-registrering auditeres ikke som `identity_linked` (BACKLOG).

## Rotere hemmeligheten

1. Lag en ny hemmelighet hos leverandøren (behold gjerne den gamle gyldig til du har restartet).
2. Oppdater verdien i miljøet (`KAUTH_IDP_ACME=...`).
3. `sudo systemctl restart kauth`.
4. Test en innlogging. Feil hemmelighet gir `reason=code_exchange`.
5. Slett den gamle hos leverandøren.

Vil du bytte navn på variabelen, oppdater `client_secret_env` i raden i samme runde.

## Deaktivere

```sql
UPDATE identity_providers SET active = 0 WHERE slug = 'acme';
```

Restart. Raden lastes ikke og logges ikke (tellelinjen viser ett færre), knappen forsvinner, og identitetene ligger igjen. Setter du `active = 1` igjen og restarter, virker innlogging som før. Midlertidig kan du også bare fjerne tilordningen til én tjeneste:

```sql
DELETE FROM service_identity_providers
WHERE service_id = 'polaris' AND provider_id = (SELECT id FROM identity_providers WHERE slug = 'acme');
```

En pågående innlogging har en state som varer opptil 10 minutter. Etter restart og fjernet tilordning avvises den med `unknown_provider`.

## Fjerne en leverandør

```sql
PRAGMA foreign_keys = ON;
DELETE FROM identity_providers WHERE slug = 'acme';
```

Med pragmaen slettes tilordningene automatisk (`ON DELETE CASCADE`). **Identitetene i `user_identities` slettes ikke.** De blir liggende med `provider='oidc'` og den gamle issueren (sikkerhetsfunn S3 i 015 F1). Det er bevisst, siden en feilslettet rad ikke skal fjerne alle kontokoblinger, men det betyr at en ny leverandør med samme issuer gjenbruker dem. Vil du rydde dem:

```sql
-- Se hva som blir borte først
SELECT u.email, i.subject FROM user_identities i JOIN users u ON u.id = i.user_id
WHERE i.provider = 'oidc' AND i.issuer = 'https://login.acme.example';

DELETE FROM user_identities WHERE provider = 'oidc' AND issuer = 'https://login.acme.example';
```

Brukerne beholdes. De mister bare koblingen og kan logge inn på andre måter. Fjern også `KAUTH_IDP_<NAVN>` fra miljøet og issueren fra `KAUTH_OIDC_ISSUERS`, og restart.

Refresh-tokens som allerede er utstedt, gjelder til de utløper eller brukeren deaktiveres. Fjerning av leverandøren trekker dem ikke tilbake.

## Ikke i prod: `KAUTH_OIDC_ALLOW_INSECURE`

`KAUTH_OIDC_ALLOW_INSECURE=true` tillater `http://` og loopback mot leverandører. Den finnes for eval-serveren og lokal utvikling, med testleverandøren `cmd/kauth-testidp`. Den slår av mye av SSRF-vernet (loopback-adresser blir nåbare), så **den skal aldri settes i prod**. kauth nekter å starte hvis den er satt uten `KAUTH_INSECURE_COOKIES=true`, og logger en advarsel ved oppstart når den er på. Kopierer du et dev-miljø til prod, fjern begge.

## Endringer krever restart

Leverandørene (rader, tilordninger, issuer-allowlist og hemmeligheter) leses én gang ved oppstart. Det gjelder alle endringer i `identity_providers`, `service_identity_providers`, `KAUTH_OIDC_ISSUERS` og `KAUTH_IDP_*`. Unntaket er `user_identities`: manuell kobling virker straks. Rekkefølge for en endring: skriv SQL og miljø, `sudo systemctl restart kauth`, `journalctl -u kauth -n 100 | grep 'idp:'`, test innlogging.

Det finnes ikke admin-UI for leverandørene ennå (planlagt i Fase 5, se [BACKLOG.md](BACKLOG.md)). Alt gjøres med `sqlite3` mot databasen, og det er lurt å ta en sikkerhetskopi først (`sqlite3 /home/lars/kauth-go/data/kauth.db ".backup <fil>"`).
