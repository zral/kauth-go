# Prosjekttillegg: solution-architect (kauth-go)

- Produktbeskrivelsen ligger i `README.md`, funksjonsoversikten i `doc/FEATURES.md`.
- Sikkerhet vurderes mot OAuth 2.0 Security BCP og OIDC Core. Vurder også isolasjon mellom tjenester.
- Integrasjonspunkter: hvilke pakker under `internal/` berøres, nye kolonner i `services`, nye ruter i `cmd/kauth/main.go`, og påvirkning på tokens/claims for eksisterende tjenester.

## Kontekst og strategi

- kauth er én CGO-fri binær med SQLite på en Raspberry Pi for små organisasjoner — ikke Keycloak. Postgres, Redis, køer og egne mikrotjenester er utenfor scope.
- **Scope-drift mot autentisering** er et anti-pattern: kauth delegerer autentisering (Google, Microsoft, magic link) og eier identitet, autorisasjon og tokenutstedelse. Forslag om egne passkeys, TOTP, passord, LDAP eller SAML skal frarådes med henvisning til produktstrategien («Delegate authentication. Own identity and authorization.»).

## Kalibrering (kauth-typisk)

### ANBEFALT — sterk analyse med klare krav

```
Feature: Generisk OIDC-føderering (014)

Problemstilling: En kunde bruker en egen OIDC-provider (f.eks. Authentik hos en
samarbeidspartner) og vil logge inn i en kauth-tjeneste uten Google/Microsoft.
Alternativ A: Hardkode én ny provider på samme måte som microsoft.go.
Alternativ B: Generisk provider-tabell (issuer, client_id, secret, scopes) koblet til
  service via join-tabell — go-oidc gjør discovery mot issuer.
Valgt: Alternativ B — gjenbruker go-oidc (allerede i go.mod), passer strategien
"delegate authentication", og unngår én Go-fil per ny provider.

Krav:
K1: En service kan aktivere 0..n generiske OIDC-providere uten kodeendring
K2: ID-token verifiseres mot providerens issuer og JWKS — ingen SkipIssuerCheck
K3: Kontokobling skjer kun på verifisert e-post (email_verified = true)
K4: client_secret vises aldri i admin-panelet etter lagring
K5: Eksisterende Google/Microsoft-flyter er uendret (regresjonstester grønne)
K6: Feil hos ekstern provider gir audit-event med provider-id, ikke stacktrace til bruker

ADN: ADN 9 — Generisk OIDC-føderering via provider-tabell

**ANBEFALT** — én ny tabell, ingen nye avhengigheter, rett i kjernen av produktstrategien.
```

---

### BETINGET ANBEFALT — uklar avgrensning

```
Feature: Webhook ved ny bruker (hypotetisk)

Problemstilling: Tjenesteeiere vil varsles når auto_register oppretter en ny bruker.
Alternativ A: Synkront HTTP-kall fra callback-handleren.
Alternativ B: Outbox-tabell + bakgrunnsjobb i internal/jobs (som Cleanup).

Uklar avgrensning:
- Hvem eier webhook-secret? Service-raden (admin-panel) → OK. Query-param → IKKE OK.
- Hvilke felter sendes? E-post og navn er persondata — databehandleravtale hos mottaker?
- Synkront kall gjør innlogging avhengig av tjenesteeierens oppetid.

Krav:
K1: Webhook sendes asynkront — innlogging feiler aldri pga. mottaker
K2: Payload signeres med HMAC-SHA256 per service-secret
K3: Payload inneholder kun sub, e-post og service_id — ingen IP eller user agent
K4: Maks 3 forsøk med backoff; feil logges som audit-event

**BETINGET ANBEFALT** — Alternativ B, forutsetter at personvernspørsmålet (K3) er
avklart med privacy-gdpr FØR implementering.
```

---

### FRARÅDET — utenfor produktstrategien

```
Feature: Egne passkeys (WebAuthn) i kauth (hypotetisk)

Analyse:
- Krever credential-lagring, attestation-håndtering, recovery-flyt og UI for
  nøkkeladministrasjon — en ny autentiseringsstack inne i kauth.
- Google og Microsoft tilbyr allerede passkeys; brukere som logger inn via dem
  får phishing-resistent innlogging uten at kauth eier noe av det.
- Strategien: "Delegate authentication. Own identity and authorization."

Alternativ A: Implementere WebAuthn med et Go-bibliotek — ny avhengighet,
  stor angrepsflate, permanent vedlikeholdsbyrde.
Alternativ B: Dokumentere at passkeys oppnås via Google/Microsoft-kontoen.
Alternativ C: Generisk OIDC-føderering mot en provider som har passkeys.

**FRARÅDET** — bryter med produktstrategien. Anbefal B nå og C når generisk
OIDC-føderering er på plass.
```
