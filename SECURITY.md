# Sikkerhetspolicy

## Rapportere sårbarheter

Hvis du oppdager en sikkerhetssårbarhet i kauth, ikke åpne en offentlig GitHub-issue. Send en privat melding via GitHub Security Advisories (Security-fanen på repoet) eller direkte til `lsoraas@gmail.com`.

Inkluder så mye detalj som du kan: hvilken versjon, hva du gjorde, hva du forventet, hva som faktisk skjedde, og en mulig konsekvens. Hvis du har en proof-of-concept eller et eksempelangrep er det nyttig — men send det privat, ikke i et offentlig forum.

Vi prøver å bekrefte mottak innen 72 timer. Reell respons og fiks avhenger av alvorlighetsgrad og kompleksitet, men hold deg med at vi gir prioritet.

## Supported versions

kauth har ingen formelle versjoner ennå. `master` er den eneste støttede grenen, og fikser kommer dit. Hvis du kjører fra en eldre commit, ta nyere `master` for sikkerhetsoppdateringer.

## Hva som er i scope

- Autentiserings- og autoriseringsflyter (OIDC, magic-link, passord, refresh-token-rotasjon)
- Token-utstedelse og -verifisering (JWT, JWKS)
- Cookie-håndtering (HttpOnly, Secure, SameSite)
- HMAC-state og state-cookie-håndtering for OIDC
- Anti-enumeration- og rate-limiting-mekanismer
- Admin-panel: autentisering, autorisering, CSRF-overflater
- Cross-host login-flyt (URL-token-passing, redirect_uri-cookie)
- Filopplasting i admin (bakgrunnsbilder)
- SQL-håndtering (selv om vi bruker sqlc og parametriserte spørringer)
- CSV-eksport (formula-injection-håndtering)

## Hva som ikke er i scope

- Sårbarheter i Cloudflare, modernc.org/sqlite, golang-jwt eller andre tredjeparts-avhengigheter — rapporter direkte til oppstrøms.
- Sosial-engineering-angrep mot administrator-brukere.
- Fysisk tilgang til serveren.
- DoS via ressursforbruk (vi har basis-grenser; ekstreme tilfeller løses oppstrøms via Cloudflare).

## Threat model i korte trekk

kauth er designet for self-hosted miljøer på et knippe tjenester. Antagelsene er:

- Kjører bak HTTPS-terminerende reverse-proxy (Cloudflare Tunnel i vårt tilfelle)
- Klient-IP kommer fra `CF-Connecting-IP`-header
- Admin-konton (brukere med `konge`-rolle) er manuelt opprettet og betrodd
- RSA-privatnøkkel er hemmelig og hostet sammen med binæren
- Resource-servere validerer JWT-er mot JWKS

Hvis disse antagelsene brytes (f.eks. kauth eksponeres direkte på et offentlig nettverk uten TLS, eller flere usanksjonerte konton har konge-rolle), er sikkerhetsmodellen ikke gyldig.

## Designvalg som er sikkerhetsmessig relevante

- Passord deaktivert som default — se README-en for resonnementet.
- Refresh-token-rotasjon med family-revocation ved gjenbruk (RFC OAuth-BCP §4.13).
- Konstant-tids HMAC-sammenligning på state-cookies.
- Anti-enumeration på magic-link og admin-login (200ms gulv + identiske responser).
- Rate-limiting på magic-link (3 forsøk per 15 min per e-post).
- Audit-isolering i goroutine — audit-feil kan aldri blokkere auth.
- Eksplisitt `Secure: true` på alle cookies (overstyrbart for lokal HTTP-utvikling via `KAUTH_INSECURE_COOKIES=true`).
- CORS er deaktivert som default (`KAUTH_CORS_ORIGINS=` tom liste = ingen CORS-headere). Aktiveres kun for spesifikke endepunkter (`/token`, `/.well-known/*`).

## Kjente begrensninger

- Vi har ikke gjort en formell penetrasjonstest. Koden er gjennomgått internt, men ekstern review er ikke utført.
- Rate-limiter for magic-link er prosess-lokal (in-memory). Hvis kauth kjører i flere instanser bak en load balancer, vil hver instans ha eget regnskap. Per nå kjøres kauth som én instans, så det er ikke et problem.
- Ingen automatisert rotasjon av RSA-signeringsnøkkelen. Manuelt bytte krever koordinert deploy.
