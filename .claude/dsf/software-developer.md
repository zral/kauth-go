# Prosjekttillegg: software-developer (kauth-go)

Stack: Go, CGO-fri binær med SQLite (sqlc), server-renderte admin-sider.

## Tester i hver fase

- `CGO_ENABLED=0 go test ./...`, `go vet ./...` og `gofmt -l .` MÅ være rene
- `go test -race ./...` er grønn for kode som berører delt tilstand (registry-cache, rate-limiter)
- Regresjonssjekk i steg 3: `go test -race ./...` + smoke-test mot lokal server med `KAUTH_SMTP_MOCK=true`

## Selv-verifiser før agenter

- Nye kolonner er med i sqlc-queries og `make sqlc` er kjørt — `internal/db/gen/` håndredigeres aldri
- Nytt `services`-felt er mappet inn i `service.Service`
- Write-operasjoner i admin skriver audit-event
- JWT-claims er uendret for eksisterende tjenester

## Kode

- [ ] Input validert ved systemgrenser: form-verdier, query-params, `redirect_uri` mot service-whitelist
- [ ] `context.Context` trådes fra request til DB-kall; feil wrappes med `fmt.Errorf("...: %w", err)`
- [ ] Ingen nye avhengigheter uten dependency-guard; koden forblir CGO-fri
- [ ] Norske kommentarer som forklarer hvorfor, engelske identifiers

## Kalibrering (i stedet for vinkjeller-eksemplene i kjernen)

```
Feature: Generisk OIDC-føderering (014)

F1 — Skjema og queries
  AK1: Migrasjon 007_oidc_providers.sql oppretter oidc_providers og service_oidc_providers med reversibel Down
  AK2: Queries i internal/db/query/oidc_providers.sql; `make sqlc` kjørt, gen/ ikke håndredigert
  AK3: service.Registry laster aktive providere per service i Warmup
F2 — Login-flyt
  AK4: GET /oidc/{provider}/start redirecter med state-HMAC og PKCE
  AK5: Callback verifiserer ID-token mot providerens issuer (ingen SkipIssuerCheck)
  AK6: Bruker uten email_verified = true avvises med audit-event `login_failed`
F3 — Admin-panel
  AK7: services-edit viser providere som avkrysningsbokser
  AK8: client_secret er write-only — tomt felt ved redigering beholder gammel verdi

Avhengighetsgraf: F1 → F2, F1 → F3, F2 || F3 (ulike pakker: auth vs. admin)
```

| Dårlig AK | God AK |
|-----------|--------|
| "Token støtter org" | "Access-token inneholder `org` = service.DefaultOrg når brukeren mangler org; verifisert i issuer_test.go" |
| "Tester for ny kode" | "`go test ./internal/auth/...` — minst 5 nye tester, inkl. ugyldig state, utløpt magic-token og deaktivert bruker" |
| "Migrer database" | "008_x.sql: `ALTER TABLE services ADD COLUMN tagline_en TEXT` — eksisterende rader uberørt, Down dropper kolonnen" |
