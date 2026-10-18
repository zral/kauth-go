# privacy-gdpr — kauth

kauth er en identitetsprovider: nesten alt den lagrer er personopplysninger, og alt den utsteder (ID- og access-tokens) er personopplysninger som sendes videre til andre tjenester.

## Rolleforståelse: operatør, tjenesteeiere og identitetsleverandører

kauth er multi-tenant. Rollen avhenger av hvem som eier tjenesten i `services`-tabellen:

- **Operatørens egne tjenester:** Operatøren av kauth-instansen er **behandlingsansvarlig** (controller) for innlogging og brukerkontoer.
- **Tjenester eid av andre organisasjoner:** Tjenesteeieren er controller for sine brukere; kauth-operatøren er **databehandler** (processor) som autentiserer og utsteder tokens på tjenesteeierens vegne. Krever databehandleravtale (art. 28).
- **Google og Microsoft** er **selvstendige controllere** for kontoen hos seg. kauth mottar en verifisert identitet (e-post, navn, `sub`) — de er ikke kauths databehandlere for selve innloggingen.

**Konsekvens:** Ved hver ny tjeneste i `services`: avklar hvem som eier den og om DPA trengs. Data fra én tjeneste skal ikke brukes til formål i en annen.

### Hva kauth deler med tjenestene

- ✅ ID/access-token-claims: `sub`, e-post, navn, roller, org — kun til tjenesten brukeren logger inn på
- ✅ `/api/me` for innlogget bruker
- ❌ Audit-logg, IP-adresser, user agent, last_login — kun synlig i admin-panelet
- ❌ Hvilke *andre* tjenester brukeren har brukt — `users` er global, men skal aldri eksponeres på tvers via claims

---

## Personopplysninger i kauth

### Kategorier og risikonivå

| Kategori | Data | Tabell | Risiko |
|----------|------|--------|--------|
| **Identifiserende** | E-post, navn | `users` | Lav |
| **Autorisasjon** | Roller, org | `users` (`roles`, `orgs`) | Lav–middels (kan avsløre ansettelsesforhold/stilling) |
| **Aktivitet** | `last_login`, `created_at`, `deactivated_at` | `users` | Lav |
| **Sesjoner** | E-post, IP, user agent, service, utløp | `refresh_tokens` | Middels |
| **Magic link** | E-post, redirect_uri, utløp | `magic_tokens` | Lav |
| **Sikkerhetslogg** | Hendelse, metode, e-post, IP, user agent, suksess, detaljer | `audit_events` | Middels |
| **Legacy-passord** | `password_hash` (bcrypt) | `users` | Middels (kun der `auth_password` er aktivt) |
| **Tekniske data** | IP i Cloudflare-logg, cookies (`auth_token`/service-spesifikt navn, `refresh_token`) | — | Lav |

### Spesielle hensyn

- **Audit-loggen er overvåking i liten skala**: den viser når og hvorfra en bruker logget inn. Tilgang skal være begrenset til admin, og retensjonen (90 dager) må holdes.
- **`details`-feltet i audit** er fritekst fra koden — det skal aldri inneholde tokens, magic-link-verdier, client secrets eller hele ID-tokens.
- **Enumeration** er et personvernproblem: magic-link gir konstant respons slik at man ikke kan finne ut om en e-post har konto.
- **Ingen art. 9-data**: kauth behandler ingen helse-, biometri- eller lokasjonsdata. Passkeys/biometri håndteres hos Google/Microsoft, ikke her.

---

## Rettslig grunnlag for behandling

| Behandling | Grunnlag | Artikkel |
|------------|----------|----------|
| Konto, innlogging, tokenutstedelse | Avtale (med tjenesten brukeren bruker) | 6(1)(b) |
| Roller/org for tilgangsstyring | Avtale / tjenesteeiers instruks | 6(1)(b), 28 |
| `auto_register` (konto opprettes ved første innlogging) | Avtale | 6(1)(b) |
| Audit-logg, IP, rate-limiting | Berettiget interesse (sikkerhet, misbruksdeteksjon) | 6(1)(f) |
| Backup | Berettiget interesse (datasikkerhet) | 6(1)(f) |

---

## Sub-prosessorer og mottakere

| Part | Data | Rolle | Notater |
|------|------|-------|---------|
| **Cloudflare** (Tunnel + DNS) | All trafikk, IP-adresser | Databehandler | DPA online; TLS termineres hos Cloudflare |
| **Google** (OIDC) | Mottar autorisasjonsforespørsel; returnerer e-post/navn/sub | Selvstendig controller | Brukeren har egen avtale med Google |
| **Microsoft Entra ID** (OIDC, `/common`) | Som Google | Selvstendig controller | Personlige og bedriftskontoer |
| **SMTP-leverandør** (magic link) | E-post, lenke med engangstoken | Databehandler | Sjekk DPA og dataresidens for leverandøren i `KAUTH_SMTP_HOST` |
| **Brevo** (magic link, valgfritt) | E-post, avsenderadresse, lenke med engangstoken | Databehandler | Brukes for tjenester med `email_from_address` satt og `KAUTH_BREVO_API_KEY` konfigurert. EU-basert (Frankrike) — sjekk DPA |
| **Tjenester i `services`** | Token-claims | Mottaker / controller | Hver tjeneste mottar kun egne brukeres claims |
| **Fremtidig generisk OIDC-provider** | Som Google | Vurderes per provider | Krever ny vurdering før aktivering |

### Tredjelandsoverføring

Google, Microsoft og Cloudflare er US-selskaper — verifiser EU-US Data Privacy Framework eller standardklausuler ved endringer. Selve databasen ligger på operatørens maskin (Raspberry Pi) og forlater den bare via backup.

---

## Lagringsperioder

| Data | Retensjon | Mekanisme |
|------|-----------|-----------|
| Magic tokens | Utløp + 24 timer | `internal/jobs` cleanup (hver time) |
| Refresh tokens | Til utløp/familieutløp | `internal/jobs` cleanup |
| Audit-events | 90 dager | `internal/jobs` cleanup |
| Brukerkonto | Til sletting/deaktivering | Admin-panelet |
| Backup | 30 dager | `scripts/backup-kauth-go.sh` (`KEEP_DAYS`) |

**Merk:** Slettede brukere lever videre i backup i inntil 30 dager og i audit-loggen (e-post som tekst) i inntil 90 dager. Dette må stå i personvernerklæringen.

---

## DPIA-vurdering

Ingen av kriteriene i art. 35(3) slår til: kauth profilerer ikke, behandler ingen art. 9-data og overvåker ikke offentlige områder.

**Konklusjon:** DPIA ikke påkrevd for dagens omfang (små organisasjoner, begrenset logg). Revurder hvis en tjeneste med sårbare brukergrupper (barn, pasienter) tas inn, eller hvis audit-loggen utvides med mer atferdsdata.

---

## Registrertes rettigheter

| Rettighet | Implementert? | Hvordan |
|-----------|---------------|---------|
| **Innsyn (art. 15)** | ⚠️ Delvis | `/api/me` viser profil/claims; audit-historikk kun via admin |
| **Retting (art. 16)** | ⚠️ Via admin | Navn hentes fra provider; roller/org settes av admin |
| **Sletting (art. 17)** | ⚠️ Via admin | Admin sletter/deaktiverer bruker; refresh-tokens må revokeres samtidig |
| **Dataportabilitet (art. 20)** | ⚠️ Manuelt | Ingen selvbetjent eksport |
| **Begrensning (art. 18)** | ✅ Ja | Deaktivering (`deactivated_at`) stopper innlogging uten å slette |
| **Innsigelse (art. 21)** | ⚠️ Manuelt | Mot audit-logging: avveies mot sikkerhetsbehov |

Når kauth er databehandler, går forespørsler via tjenesteeieren (controller), som instruerer operatøren.

### Gjenstående forbedringer

1. Eksport av all data om én e-post (bruker, tokens, audit) fra admin-panelet
2. Sletting som også revokerer alle refresh-familier og anonymiserer audit-rader
3. Lenke til personvernerklæring på login-siden per tjeneste

---

## Personvernerklæring — innholdskrav

Personvernerklæringen (art. 13) for operatørens kauth-instans MÅ inneholde:

```
[ ] Behandlingsansvarlig og kontaktpunkt
[ ] Hvilke personopplysninger (e-post, navn, roller/org, IP, user agent, innloggingstidspunkt)
[ ] Formål per kategori (innlogging, tilgangsstyring, sikkerhet)
[ ] Rettslig grunnlag per formål (avtale + berettiget interesse)
[ ] Mottakere (Cloudflare, Google, Microsoft, SMTP-leverandør/Brevo, tjenestene brukeren logger inn på)
[ ] Overføring til tredjeland (US — EU-US DPF)
[ ] Lagringsperioder (audit 90 dager, backup 30 dager, konto til sletting)
[ ] Registrertes rettigheter og klagerett til Datatilsynet
[ ] Ingen automatiserte avgjørelser med rettslig effekt (rollebasert tilgang settes av admin)
[ ] Cookies — kun teknisk nødvendige (HttpOnly access- og refresh-token, språkvalg)
[ ] Dato for siste oppdatering
```

---

## Tillegg til kjernens sjekklister

```
[ ] For hvilken tjeneste? Er kauth controller eller processor for den? DPA på plass?
[ ] Ny identitetsleverandør? Krever ny vurdering før aktivering
[ ] Lagringsperiode — dekket av cleanup-jobben i internal/jobs?
[ ] Tilgangskontroll i admin — audit og IP bare synlig der
[ ] Nye claims i tokens? Minimer — kun det tjenesten trenger, aldri på tvers av tjenester
[ ] Audit-events: ingen tokens/secrets i `details`
[ ] slog-logging til journald: ingen e-post + IP-kombinasjoner utover audit-tabellen
[ ] Sletting av bruker/service (ON DELETE): revokeres refresh-familier, hva skjer med audit?
[ ] Backup-konsekvens: data lever 30 dager i backup etter sletting
```

---

## Referanser

- OpenID Connect Core 1.0 §5 (standard claims) — grunnlag for claim-minimering
- Kode: `internal/jobs/cleanup.go` (retensjon), `internal/audit/service.go` (audit), `internal/auth/cookies.go` (cookies)
- Funksjonsoversikt: `doc/FEATURES.md` (Audit-logg, Datamodell)
