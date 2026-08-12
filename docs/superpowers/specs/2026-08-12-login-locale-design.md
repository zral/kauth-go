# Locale-støtte for login-flyten

**Dato:** 2026-08-12
**Status:** godkjent design

## Problem

Login-sidene finnes bare på norsk. Alle tekster er hardkodet i `templates/login.html` og
`templates/magic-login.html`, og magic-link-e-posten har norsk emne og brødtekst i
`internal/mail/mail.go`. Tjenester som `auth.spekto.live` har brukere utenfor Norge.

## Mål

Tre språk på de bruker-vendte login-sidene og i magic-link-e-posten: norsk (`nb`),
engelsk (`en`) og tysk (`de`). Engelsk er fallback for alle andre nettleserspråk og for
requests uten `Accept-Language`.

## Utenfor scope

- **Admin-panelet** (`templates/admin/*`) forblir norsk.
- **`http.Error`-tekstene** i `internal/auth/*.go` forblir norske. Merk at
  `password.go` svarer «ugyldig e-post eller passord» som plain text — en bruker-vendt
  melding som bryter språket. Mønsteret for å fikse det finnes (`/login?error=<kode>` →
  oversatt tekst), men `auth_password` er ikke aktivt på spekto. Eget arbeid.
- **`redirect_uri` i magic-login-`fetch()`**. `fetch()` poster til `/magic-login` uten
  query-params, mens `RequestLink` leser `redirect_uri` fra query. Det fungerer i dag
  fordi `login.html` også setter en `redirect_uri`-cookie. Denne implementasjonen legger
  `lang` på POST-URL-en men rører ikke `redirect_uri`-håndteringen.

## Arkitektur

### `internal/i18n` — ny bladpakke

Ingen avhengigheter utover stdlib. Ingen `golang.org/x/text` — `Accept-Language`-parsing
er ~30 linjer, og prosjektet verdsetter en slank binær.

Delt i to filer så oversettelses-endringer ikke rører logikk:

- `i18n.go` — `Strings`-typen, `Resolve`, `FromRequest`, `Get`, `Links`
- `catalog.go` — bare `catalog`-mappet

```go
const Fallback = "en"

// Get returnerer katalogen for locale, eller Fallback-katalogen for ukjent locale.
func Get(locale string) Strings

// FromRequest er ergonomi-wrapperen handlerne bruker.
func FromRequest(r *http.Request) string  // Resolve(query "lang", header "Accept-Language")

// Resolve velger locale. Eksplisitt lang-param vinner over nettleserpreferanse.
func Resolve(langParam, acceptLanguage string) string

// Links bygger språkvelgeren for gjeldende URL.
func Links(active string, u *url.URL) []Link

type Link struct {
    Code   string // "nb" — brukes i href og som lang-attributt
    Label  string // "NO" — vises
    Name   string // "Norsk" — title/aria-label
    Href   string // path + query med lang satt
    Active bool
}
```

**`Resolve`-prioritet:** `?lang=` (hvis støttet) → `Accept-Language` → `"en"`.
En ustøttet `?lang=fr` faller videre til `Accept-Language`, den avbryter ikke kjeden.

**Normalisering:** lowercase, primary subtag (`de-DE` → `de`), og `no`/`nn`/`nb` → `nb`.
Norsk sendes som alle tre av ulike nettlesere.

**`Accept-Language`-parsing:** splitt på komma, les `;q=`-vekt (default 1.0), sorter
synkende og stabilt, returner første støttede treff. Ugyldig `q` gir vekt 0.

**`Links`:** kopierer `u.Query()`, setter `lang`, returnerer `u.Path + "?" + q.Encode()`.
Path-only href, så host aldri lekker inn i markup. Dette bevarer `service` og
`redirect_uri` automatisk. Aktivt språk får `Active: true` og rendres ikke som lenke.

### Template-data

`LoginPageData` i `internal/auth/login.go` får tre felt:

```go
Locale    string       // til <html lang="{{.Locale}}">
T         i18n.Strings // alle tekster
Languages []i18n.Link  // språkvelgeren
```

Templatene bruker `{{.T.Feltnavn}}`. Fordelen over map-oppslag: en skrivefeil i
feltnavnet gir render-feil, ikke en stille tom streng.

JS-strengene i `magic-login.html` injiseres som et objekt:

```html
var I18N = { sending: {{.T.MagicSending}}, submit: {{.T.MagicSubmit}} };
```

`html/template` quoter og escaper selv i JS-kontekst — ingen manuelle anførselstegn.

### Strenginventar

`Strings` er én flat struct. Felt gjenbrukes der teksten er identisk (`SignIn` er både
`<title>`-prefiks og passord-knappens tekst i alle tre språk).

| Felt | nb (dagens tekst) |
|---|---|
| `SignIn` | Logg inn |
| `EmailPlaceholder` | E-postadresse |
| `PasswordPlaceholder` | Passord |
| `Or` | eller |
| `ContinueWithGoogle` | Fortsett med Google |
| `ContinueWithMicrosoft` | Fortsett med Microsoft |
| `SignInWithEmailLink` | Logg inn med e-postlenke |
| `MagicPageTitle` | E-postinnlogging |
| `MagicSubmit` | Send innloggingslenke |
| `MagicSending` | Sender… |
| `MagicCheckInbox` | Sjekk innboksen din |
| `MagicSentToBefore` | Vi har sendt en innloggingslenke til |
| `MagicSentToAfter` | . Klikk på lenken for å logge inn. |
| `MagicValidMinutes` | Lenken er gyldig i 15 minutter. |
| `BackToSignIn` | Tilbake til innlogging |
| `ErrAccessDenied` | Tilgang nektet. |
| `ErrInvalidRedirect` | Ugyldig retur-adresse. Start innloggingen på nytt. |
| `ErrExpiredLink` | Lenken er utløpt eller allerede brukt. Prøv igjen. |
| `ErrTooManyRequests` | For mange forespørsler. Vent noen minutter og prøv igjen. |
| `MailSubject` | Din innloggingslenke |
| `MailBody` | Hei!\n\nKlikk for å logge inn (gyldig 15 min):\n\n%s\n\n… |

**`MagicSentToBefore`/`-After` er delt i to på grunn av tysk ordstilling.** Setningen
har e-postadressen i midten, injisert av JS i et `<span>`. Tysk plasserer verbet etter
objektet:

- `de`: «Wir haben einen Anmeldelink an» + *e-post* + « gesendet. Klicken Sie …»
- `nb`: «Vi har sendt en innloggingslenke til» + *e-post* + «. Klikk på lenken …»

Ett samlet felt med placeholder ville også fungert, men to felt holder templaten fri for
`printf`-logikk.

**Bevisste forenklinger:**

- `invalid_redirect` har i dag to nesten like tekster («… på nytt.» i `login.html`,
  «… på nytt fra applikasjonen.» i `magic-login.html`). Konsolideres til én.
- `MagicValidMinutes` og `MailBody` hardkoder «15 minutter», som duplikatet i
  `magic.go` allerede gjør. Ikke parametrisert.
- `MailBody` inneholder nøyaktig én `%s` (innloggingslenken). En test håndhever det.

### Språkvelger

`<nav class="lang">` under kortet i begge templatene: `NO · EN · DE`. Aktivt språk er
ren tekst, de andre er lenker. Ingen JS, ingen cookie — `?lang=` i URL-en er hele
mekanismen. Diskret styling som matcher temaet (dempet farge, `.8rem`).

### Locale gjennom flyten

| Sted | Endring |
|---|---|
| `ServeLogin` | `i18n.FromRequest(r)` → `Locale`, `T`, `Languages` |
| `login.html` | magic-link-knappen får `&lang={{.Locale}}` server-side |
| `ShowForm` | samme oppslag som `ServeLogin` |
| `magic-login.html` | `fetch()` poster til `/magic-login?lang=<locale>` |
| `RequestLink` | `i18n.FromRequest(r)` → sendes til mailer |
| `mail.SendMagicLink` | ny signatur: `(to, fromName, linkURL, locale string)` |
| `admin/auth.go:132` | kaller med `"nb"` — admin-e-post forblir norsk |

OIDC-knappene (`/social-login`, `/ms-oidc-login`) får ikke `lang`. Google og Microsoft
håndterer språk selv, og callback lander på `/dispatch`, ikke på en oversatt side.

## Testing

Ny `internal/i18n/i18n_test.go`:

- **`TestCatalogComplete`** — reflekterer over `Strings`-feltene og feiler hvis noen
  locale har et tomt felt. Dette er sikkerhetsnettet mot halvferdige språk: legger man
  til et felt uten å oversette det, feiler testen i stedet for at siden viser blankt.
- **`TestMailBodyHasOnePlaceholder`** — nøyaktig én `%s` per locale.
- **`TestResolve`** — table-driven: `?lang=DE` (case-insensitivt), `?lang=fr` (ustøttet,
  faller videre), `de-DE,de;q=0.9,en;q=0.8` → `de`, `nb-NO` → `nb`, `no` → `nb`,
  `nn` → `nb`, `fr` → `en`, tom header → `en`, `en;q=0.1,de;q=0.9` → `de` (q-sortering).
- **`TestLinksPreserveQuery`** — `service` og `redirect_uri` overlever, `lang` settes,
  href er path-relativ.

Ny `internal/auth/login_render_test.go`:

- Rendrer `login.html` og `magic-login.html` for hver locale mot en syntetisk
  `gen.Service`, og feiler på render-feil. Dette fanger feltnavn-typo i templatene, som
  er den ene feilklassen struct-tilnærmingen ikke fanger ved kompilering.
- Sjekker at forventet tekst finnes i output per locale.

Testene krever ingen live-provider, så de bryter ikke med konvensjonen i CLAUDE.md om at
OIDC-handler-integrasjonstester er bevisst utelatt.

## Filer som berøres

**Nye:** `internal/i18n/i18n.go`, `internal/i18n/catalog.go`,
`internal/i18n/i18n_test.go`, `internal/auth/login_render_test.go`

**Endres:** `internal/auth/login.go`, `internal/auth/magic.go`, `internal/mail/mail.go`,
`internal/admin/auth.go`, `templates/login.html`, `templates/magic-login.html`

Ingen migrasjon, ingen `sqlc`-regenerering, ingen nye env-variabler.
