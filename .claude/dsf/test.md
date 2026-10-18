# Prosjekttillegg: test (kauth-go)

Stack: Go, SQLite (sqlc/goose), server-rendrede maler. Tenant-grensen er **tjenesten**.

## Enhetstester (Go)

Testfiler `*_test.go` ved siden av koden (f.eks. `internal/token/refresh_test.go`),
tabelldrevne der det gir mening. Full verifisering fra prosjektroten, alle skal være grønne:

```bash
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go test ./...
go test -race ./...          # krever CGO internt; kjøres uten CGO_ENABLED=0
go vet ./...
gofmt -l .                   # skal ikke liste noe
command -v govulncheck >/dev/null && govulncheck ./...   # hvis installert
go test -run TestRotate ./internal/token                 # én test
```

```go
// Tester for XXX — kort beskrivelse av hva featuren verner mot.
package token_test

func TestRotate_Reuse_RevokeFamily(t *testing.T) {
	db := newStubRefreshDB() // stub av token.RefreshQuerier, se refresh_test.go
	svc := token.NewRefreshService(db, audit.NewNoop())
	ctx := context.Background()

	plain, err := svc.Issue(ctx, testUser(), testService(), "127.0.0.1", "ua")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	result, err := svc.Rotate(ctx, plain, "127.0.0.1", "ua")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	// Gjenbruk av et allerede konsumert token skal revokere hele familien.
	if _, err := svc.Rotate(ctx, plain, "127.0.0.1", "ua"); err == nil {
		t.Fatal("forventet feil ved gjenbruk av konsumert refresh-token")
	}
	if _, err := svc.Rotate(ctx, result.NewToken, "127.0.0.1", "ua"); err == nil {
		t.Fatal("familien skulle vært revokert, men nyeste token virker fortsatt")
	}
}
```

**Test-hjelpere:**
- `token.NewIssuerForTest()` og `(*Issuer).IssueAdminForTest(email, role)` i `internal/token/testing.go`
- `service.NewRegistryForTest([]gen.Service{...})` i `internal/service/testing.go` — registry uten DB-warmup
- `openTestDB(t)` i `internal/db/testhelper_test.go` — in-memory SQLite med migrasjoner (kun i `db`-pakken)
- `httptest.NewRecorder()` / `httptest.NewRequest()` for handler-tester

Ingen nettverk: Google, Microsoft og SMTP/Brevo treffes aldri. Handler-integrasjonstester mot
live-providere er bevisst utelatt (se CLAUDE.md).

## Byggverifisering

- Endres `internal/db/query/` eller migrasjoner, skal diffen i `internal/db/gen/` samsvare (kjør `make sqlc` hvis sqlc finnes)
- Prod kjører på samme maskin — start aldri kauth på prod-porten

## HTTP-testing

Mot eval-serveren (`http://127.0.0.1:8091`, startet av hovedagenten med
`bash scripts/run-eval-server.sh`). Magic-link-lenker hentes fra eval-serverens stdout
(`KAUTH_SMTP_MOCK=true`). Admin-rute uten admin-token → redirect til `/admin/login`.

## Grenseverdier

- **Tomt**: tjeneste uten aktive auth-metoder, bruker uten roller/orgs
- **Første gang**: første innlogging med `auto_register` på og av
- **Token-tilstand**: `alg: none`, token akkurat utløpt (`exp == now`)
- **Rate limit**: magic-link 3/15 min per e-post — fjerde forespørsel gir samme respons, men ingen ny e-post
- **Utløp**: admin-token etter admin-TTL; cleanup-jobben sletter utløpte rader uten å røre gyldige

## Tenant-isolasjon

- Token for tjeneste A godtas ikke som B (`aud`), og refresh for A gir ikke token for B
- `redirect_uri`/`auth_host` som matcher feil tjeneste, eller ingen, gir avvisning — ikke fallback til default-tjenesten
- Cookie-navn per tjeneste kolliderer ikke; logout i A rydder ikke B utilsiktet
- Deaktivert metode (f.eks. `auth_password = 0`) avvises server-side

## Sjekklister

### Tokens og JWKS
- [ ] Access-token har `iss`, `aud`, `sub`, `exp`, `iat` og riktig `kid`; signatur verifiserer mot `/.well-known/jwks.json`
- [ ] TTL hentes fra tjenesten, admin-token fra egen TTL
- [ ] Refresh-rotasjon: nytt token per bruk, gjenbruk revokerer hele familien

### Login-flyter
- [ ] State er HMAC-signert og bundet til tjenesten; manipulert state avvises
- [ ] Callback validerer `redirect_uri` mot tjenestens `callback_url` med eksakt match
- [ ] Magic-link: konstant respons; token engangs og tidsbegrenset
- [ ] Passord: feil passord og ukjent bruker gir samme respons og omtrent samme tid

### Admin-panel
- [ ] Alle `/admin/*`-ruter unntatt login/verify/google-* krever admin-token
- [ ] Skriveoperasjoner skriver audit-event
- [ ] CSV-eksport escaper felt som starter med `=`, `+`, `-`, `@`

### SQLite
- [ ] WAL-modus aktiv; SQL kun via sqlc

## Rapport

Teststatuslinjen: `**go test:** … · **-race:** … · **vet:** … · **gofmt:** … · **govulncheck:** [ren/funn/ikke installert]`

Mutasjonseksempler: fjern `aud`-sjekken, bytt eksakt match med `strings.HasPrefix`, fjern
family-revokeringen, bytt `subtle.ConstantTimeCompare` med `==`.

## Kalibrering (kauth-typisk)

### BESTÅTT — alle tester grønne, meningsfulle assertions

```
Feature: Refresh-rotasjon med family-revocation (F2)

go test ./...        ok (alle pakker)
go test -race ./...  ok
go vet ./...         ren
gofmt -l .           tom
govulncheck          ikke installert — hoppet over

AK-verifisering:
- AK1 rotasjon gir nytt token → refresh.go:122, TestRotate_IssueAndRotate
- AK2 gjenbruk revokerer familien → refresh.go:140, TestRotate_Reuse_RevokeFamily
- AK3 family-utløp arves → refresh.go:101, TestRotate_FamilyExpiresAt_Inherited

Mutasjon: fjernet RevokeFamilyTokens-kallet → TestRotate_Reuse_RevokeFamily rød.
Gjenopprettet, git diff ren.

**BESTÅTT** — alle AK dekket, mutasjon fanget
```

---

### FEILET — tester feiler eller mangler

```
Feature: Hypotetisk ny redirect_uri-validering i callback

go test ./internal/auth/...  FAIL
--- FAIL: TestCallback_RedirectURIExactMatch/trailing_slash
    want 400, got 302 (Location: https://app.example/callback/)

go test -race ./...  WARNING: DATA RACE i service.(*Registry).Resolve
  (cache-map lest uten lås mens Warmup skriver)

Manglende borderline-caser:
- redirect_uri med fragment (#) ikke testet
- http vs https for samme host ikke testet
- AK3 («deaktivert tjeneste avvises») har kode, men ingen test

**FEILET** — 1 test feiler, 1 data race, 3 borderline-caser mangler
```
