# Prosjekttillegg: code-review (kauth-go)

Stack: Go, SQLite via sqlc/goose, server-rendrede `html/template`-maler. kauth er en
OIDC-identitetsprovider som utsteder tokens flere tjenester stoler på — en feil her er en
feil i alle tjenestene samtidig.

Ekstra alvorlighetsmarkører: token for feil bruker/tjeneste er **Kritisk**; data race er
**Alvorlig**; goroutine uten stopp og manglende context er **Moderat**.

## Sikkerhet (OIDC/JWT)

- [ ] JWT-validering låser `alg` til RS256 (aldri `none`, aldri HS256 med offentlig nøkkel som secret) og sjekker `iss`, `aud`, `exp` (og `nbf`/`iat` der relevant)
- [ ] `kid` slås opp i kjent nøkkelsett — ukjent `kid` avvises, ikke fallback til første nøkkel
- [ ] Access-, refresh- og admin-tokens kan ikke forveksles (egen `typ`/audience/lagring)
- [ ] `state` er signert og bundet til tjenesten
- [ ] Identitet fra Google/Microsoft knyttes på `sub`/`oid`, eller e-post kun når `email_verified` er sann (nOAuth)
- [ ] Admin-ruter ligger inne i gruppen bak `admin.AdminAuthMiddleware` i `cmd/kauth/main.go`
- [ ] Service-oppslaget avgjør hvilke auth-metoder som er lov — deaktivert metode avvises server-side
- [ ] Secrets kun fra env via `internal/config`; aldri i logg, feilmelding, mal eller admin-visning
- [ ] Sammenligning med `crypto/subtle` eller `hmac.Equal`; tilfeldighet fra `crypto/rand`, aldri `math/rand`

## Go

- [ ] Ingen ignorerte `error`-returverdier (`_ =` eller utelatt) uten kommentar
- [ ] Errors wrappes med `fmt.Errorf("...: %w", err)` og sjekkes med `errors.Is/As`
- [ ] `r.Context()` sendes videre til DB- og utgående HTTP-kall; ingen `context.Background()` i request-sti
- [ ] Goroutiner har stoppbetingelse (context, done-kanal)
- [ ] Delt tilstand (registry-cache, rate-limit-map) er beskyttet med mutex/atomics — `go test -race` er grønn
- [ ] `defer rows.Close()` / `defer resp.Body.Close()` rett etter feilsjekk
- [ ] Utgående HTTP-klienter har timeout (ikke `http.DefaultClient`)
- [ ] `gofmt` og `go vet` er rene

## HTTP-handlere og maler

- [ ] Handlere returnerer etter `http.Error`/`http.Redirect`
- [ ] Muterende admin-operasjoner kun på POST, med CSRF-vern (SameSite + token eller origin-sjekk)
- [ ] Maler bruker `html/template` (aldri `text/template` for HTML), ingen `template.HTML`/`template.URL` på brukerdata
- [ ] Cookies har `HttpOnly`, `Secure` (unntatt `KAUTH_INSECURE_COOKIES`), `SameSite` og riktig `Path`/navn per tjeneste
- [ ] Ny brukersynlig tekst finnes i i18n-katalogen for alle språk
- [ ] Muterende admin-operasjoner skriver audit-event via `audit.Service`

## Database (SQLite/sqlc/goose)

- [ ] Alle queries går via sqlc (`internal/db/query/` → `make sqlc`) — `internal/db/gen/` er ikke håndredigert
- [ ] Ingen SQL bygd med `fmt.Sprintf`
- [ ] Flerstegs-skriving (rotasjon, revokering, opprett bruker + audit) i én transaksjon med `defer tx.Rollback()`
- [ ] Ny goose-migrasjon følger `001_init.sql`-mønsteret, har `-- +goose Down` og kjører på eksisterende data
- [ ] Indekser på token-hash, e-post, family-id
- [ ] Nye `services`-kolonner er tatt med i `service.Service` og registry-warmup

## Vanlige feller

1. **`strings.HasPrefix(uri, svc.CallbackURL)`** på redirect_uri
2. **Ignorert error fra `Rotate`/`Consume`**: token utstedes selv om konsumeringen feilet → reuse-deteksjon brytes
3. **Uverifisert e-post som identitet**: konto-overtakelse via Microsoft-konto med fremmed e-post
4. **Rate-limit-map uten lås**: data race og panikk under last
5. **`context.Background()` i handler**: DB-kall overlever klienten, shutdown henger
6. **Hardkodet `http://localhost`**: bryter `iss` bak Cloudflare Tunnel

## Kalibrering (kauth-typisk)

| Grad | Eksempel |
|------|----------|
| K | redirect_uri-prefiksmatch, `alg` ikke låst, admin-rute utenfor `AdminAuthMiddleware`, feil fra `VerifyState` ignorert så callback faller til default-tjeneste |
| A | ignorert error i token-sti, data race, intern info i feilmelding |
| M | ticker-goroutine uten `ctx.Done()`-gren, cleanup-feil som ikke logges, manglende indeks |
| S | WHAT-kommentarer i stedet for WHY |
