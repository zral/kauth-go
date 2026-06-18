# kauth

Lettvekts OIDC-identitetsprovider i Go. Erstatter Keycloak / Zitadel for små til mellomstore organisasjoner som vil ha sentral innlogging uten å sette av en virtuell maskin til oppgaven.

En statisk binær på ~14 MB. Lever på en Raspberry Pi 5 med ~25 MB RAM i drift. SQLite for lagring, RS256-signerte JWT-er for utstedelse, og Cloudflare Tunnel foran for TLS og DDoS-skjerming.

Brukes i produksjon på `auth.klarsyn.net`, `auth.spekto.live` og `auth.lilleklo.work`.

## Hva kauth gjør

- Utsteder JWT-er (RS256) for innloggede brukere
- Roterer refresh-tokens med reuse-deteksjon (RFC OAuth-BCP §4.13)
- Eksponerer JWKS og OpenID Discovery på `/.well-known/`
- Tilbyr fire innloggingsveier per tjeneste: Google OIDC, Microsoft OIDC, magic-link på e-post, og passord (sistnevnte deaktivert som standard — se *Det passordløse valget* nedenfor)
- Sentral brukeradministrasjon: ett admin-panel for alle tjenestene
- Auditlogg med 90 dagers retensjon

Hver tjeneste konfigureres datadrevet i `services`-tabellen. Onboarding er én INSERT.

## Komme i gang lokalt

```bash
git clone git@github.com:zral/kauth-go.git
cd kauth-go
make build           # bygger bin/kauth
```

Minimum konfig via miljøvariabler:

```bash
export KAUTH_DB_PATH=./data/kauth.db
export KAUTH_ISSUER=http://localhost:8080
export KAUTH_BASE_URL=http://localhost:8080
export KAUTH_PRIVATE_KEY_PATH=./secrets/privateKey.pem
export KAUTH_PUBLIC_KEY_PATH=./secrets/publicKey.pem
export KAUTH_OIDC_STATE_SECRET=$(openssl rand -base64 48)
export KAUTH_SMTP_MOCK=true
export KAUTH_INSECURE_COOKIES=true   # bare for lokal HTTP-utvikling

./bin/kauth
```

Generer RSA-nøkler hvis du ikke har dem fra før:

```bash
openssl genpkey -algorithm RSA -out secrets/privateKey.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in secrets/privateKey.pem -out secrets/publicKey.pem
```

Migrasjoner kjører automatisk ved oppstart.

## Onboarde en ny tjeneste

En tjeneste = én rad i `services`-tabellen. Eksempel for en imaginær app "polaris":

```sql
INSERT INTO services (
    id, display_name, domain, callback_url,
    email_from_name,
    auth_google, auth_magic_link, auth_microsoft, auth_password,
    auth_host,
    google_client_id, google_client_secret,
    default_role, default_org, auto_register,
    theme, accent_color, jwt_cookie_name,
    access_token_ttl, refresh_token_max_age,
    active, updated_at
) VALUES (
    'polaris', 'Polaris', 'polaris.example.com', 'https://polaris.example.com/auth/callback',
    'Polaris',
    1, 1, 0, 0,
    'auth.polaris.example.com',
    NULL, NULL,                            -- bruk global Google-klient
    'user', 'polaris', 1,                  -- auto-registrer som user/polaris
    'light', '#2563EB', 'auth_token',
    'PT30M', 'P30D',
    1, datetime('now')
);
```

Felter du nesten alltid setter:

| Felt | Forklaring |
|---|---|
| `id` | Kort, kebab-fri slug. Brukes i URLer og JWT-claims. |
| `domain` | App-domenet. Brukes for å rute callbacks tilbake til riktig sted. |
| `callback_url` | Hvor brukeren sendes etter vellykket login. Må eksakt matche app-ens callback-endepunkt. |
| `auth_host` | Hvilket hostname auth-siden serveres på for denne tjenesten. Lar deg ha branded URL per tjeneste (`auth.spekto.live` osv). |
| `default_org` | Hva nye brukere automatisk får i `org`-claim. App-en bruker dette for tilgangskontroll. |
| `auto_register` | `1` lar nye brukere bli opprettet ved første login. `0` betyr at admin må opprette dem først. |
| `access_token_ttl` / `refresh_token_max_age` | ISO 8601-varigheter. Kort access-TTL + lang refresh = god balanse mellom sikkerhet og UX. |

Når raden er på plass, peker du tjenestens login-flyt mot `https://<auth_host>/login?redirect_uri=https://<din-app>/auth/callback`. Resten ordner kauth.

### Bakgrunnsbilde

Legg bildet i `static/`-katalogen og deploy:

```bash
cp polaris-hero.jpg static/
git add static/polaris-hero.jpg
git commit -m "feat(static): bakgrunnsbilde for polaris"
make deploy
```

Sett deretter `bg_image` på service-raden:

```sql
UPDATE services SET bg_image = '/polaris-hero.jpg' WHERE id = 'polaris';
```

Login-templaten setter automatisk `background: url('/static/polaris-hero.jpg') center/cover no-repeat fixed`. Innholdet på `static/` serves på `/static/`-prefiks. Bilder bør være under 1 MB — webp eller komprimert jpeg gir best vekt-til-kvalitet.

## Sette opp Google OIDC

Per tjeneste, eller globalt for alle. Per tjeneste anbefales hvis tjenestene tilhører ulike domener — Google krever at redirect-URI-en er hvitlistet på OAuth-klienten.

1. I [Google Cloud Console](https://console.cloud.google.com/) → APIs & Services → Credentials → Create OAuth Client ID → Web application.
2. Authorized redirect URI: `https://<auth_host>/callback` for hver auth-host tjenesten din skal støtte.
3. Sett `google_client_id` og `google_client_secret` på service-raden — eller `KAUTH_GOOGLE_CLIENT_ID` / `KAUTH_GOOGLE_CLIENT_SECRET` globalt hvis alle tjenestene deler én klient.
4. Sett `auth_google = 1` på tjenesten.

## Sette opp Microsoft OIDC

Samme oppskrift, men i [Microsoft Entra Admin Center](https://entra.microsoft.com/) → App registrations → New registration.

1. Account types: Accounts in any organizational directory and personal Microsoft accounts (gir bredeste dekning via `/common`-endepunktet).
2. Redirect URI (Web): `https://<auth_host>/ms-callback`.
3. Certificates & secrets → New client secret.
4. Lagre `MicrosoftClientID` og `MicrosoftClientSecret` på service-raden eller globalt.
5. Sett `auth_microsoft = 1`.

Microsoft-flyten bruker `/common`-endepunktet og verifiserer ID-tokenet med `SkipIssuerCheck`, siden personlige kontoer og bedriftskontoer har ulike `iss`-claims. Signaturverifikasjon er fortsatt streng.

## Sette opp magic-link (e-postinnlogging)

Hvilken som helst SMTP-server går. Vi bruker [Resend](https://resend.com) i prod.

```bash
export KAUTH_SMTP_HOST=smtp.resend.com
export KAUTH_SMTP_PORT=587
export KAUTH_SMTP_USER=resend
export KAUTH_SMTP_PASSWORD=re_xxxxxxxxx
export KAUTH_SMTP_FROM=noreply@yourdomain.com
export KAUTH_SMTP_STARTTLS=true
```

Sett `auth_magic_link = 1` på tjenesten. Brukeren får en lenke med 15 minutters levetid, engangsbruk, atomisk konsumert i databasen. Tre forsøk per e-postadresse per 15 minutter — alt over blir stille slipt vekk (anti-enumeration: alle responser ser like ut).

## Det passordløse valget

kauth støtter passord — feltet finnes, koden er der — men det er av som standard, og vi anbefaler å la det stå sånn.

Argumentet er ikke at passord er teknisk umulig, eller at magic-link er kvalitativt sterkere kryptografi. Magic-link og "send reset-link" har samme grunnleggende risikomodell — hvis e-postkontoen kompromitteres, er begge tapt. Phishing fungerer mot begge.

Forskjellen ligger i hvor mange uavhengige credentials vi forvalter per bruker. Passord + e-post-recovery = to credentials, to lekkasje-veier, to phishing-scenarier. Bare e-post = én credential, samme angrepsflate, men ingen tilleggsrisiko fra passord-laget — gjenbruk på tvers av tjenester, dårlige hash-algoritmer, lekkede passordbaser, reset-flyter som glipper. Færre lag, mindre overflate.

Og passord skalerer dårlig på tvers av tjenester. Jo flere tjenester en bruker må holde styr på, jo mer sannsynlig er det at samme passord brukes på alle. Det betyr at vår tjeneste plutselig deler skjebne med den svakeste passord-lagringen i hele økosystemet brukeren er innom — uavhengig av hvor pedantiske vi er med bcrypt og rotasjon. Hver gang vi krever et nytt passord, bidrar vi marginalt til dette problemet. Den belastningen ønsker vi ikke å legge på brukerne våre.

Når vi flytter all autentisering til Google, Microsoft og e-postbaserte engangslenker, gjør vi tre ting samtidig:

- **Vi outsourcer den vanskelige delen.** Identitetsleverandørene har sikkerhetsbudsjett vi ikke har. De ruller ut FIDO2, anomali-deteksjon, device-binding og phishing-resistans uten at vi løfter en finger. Det er en god deal.
- **Vi fjerner friksjon der det betyr noe.** Magic-link tar 12 sekunder. Google-knappen er to klikk. Ingen glemte passord, ingen reset-mail-er, ingen "passordet ditt utløper om 14 dager". Brukerne får mer tid til det de egentlig skulle gjøre.
- **Vi tar en politisk posisjon.** Å droppe passord er en uttalelse om hva vi mener autentisering bør være i 2026. Det signaliserer til brukerne — og til oss selv — at vi velger den moderne veien selv når det er litt ubehagelig. Det er enklere å holde linja når den er trukket.

Det er fortsatt edge cases. En engangsbruker som ikke har Google og ikke vil oppgi e-post er én av dem. Vi løser dem som engasjementer, ikke som arkitektur.

## Drift

**Deploy til Pi5:**

```bash
make deploy   # cross-compiler til arm64, scp + systemctl restart
```

`kauth.service`-unitten kjører binæren som ikke-root, med WAL-aktivert SQLite, graceful SIGTERM-håndtering og automatisk restart.

**Backup:** `scripts/backup-kauth.sh` (i søsterrepoet) tar daglig kopi av databasen via cron. SQLite med WAL er trygt å kopiere live.

**Observability:** strukturerte logger via Go `slog`. Cleanup-jobber (magic-tokens, refresh-tokens, gamle audit-events) kjører hver time i en bakgrunns-goroutine.

**Cloudflare Tunnel:** kauth lytter på localhost. Tunnel termimerer TLS og leverer trafikken via Cloudflare-kanten — så vi får DDoS-beskyttelse, ekte klient-IP via `CF-Connecting-IP`-header, og null hull i brannmuren.

## Arkitektur i grove trekk

- **`cmd/kauth`** — entry point. Konfig, DB-oppstart, router-wiring, graceful shutdown.
- **`internal/auth`** — innloggings-handlere (Google, Microsoft, magic-link, password), dispatch, login-side, middleware.
- **`internal/token`** — JWT-utstedelse, JWKS, refresh-rotasjon.
- **`internal/admin`** — admin-panel: brukeradministrasjon, audit-logg, service-konfig, magic-link- og Google-innlogging for admin.
- **`internal/service`** — tjeneste-resolver med cache. Bestemmer hvilken tjeneste en innkommende request tilhører basert på redirect-URI eller auth-host.
- **`internal/db`** — sqlc-generert databaselag mot SQLite (modernc.org/sqlite, CGO-fri).
- **`internal/jobs`** — bakgrunnsjobber.

## Lisens

Bruk som du vil. Hvis du gjør noe lurt eller fanger en bug, send en PR.
