# Locale-støtte for login-flyten — implementasjonsplan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Login-sidene og magic-link-e-posten skal finnes på norsk, engelsk og tysk, med engelsk som fallback for alle andre nettleserspråk.

**Architecture:** En ny bladpakke `internal/i18n` holder en flat `Strings`-struct per locale i et Go-map. Handlerne slår opp locale fra `?lang=` eller `Accept-Language`, legger `Strings` på template-dataen, og templatene bruker `{{.T.Feltnavn}}` — slik at en skrivefeil gir render-feil framfor en tom streng. Ingen DB-endring, ingen nye env-variabler.

**Tech Stack:** Go 1.25.7, stdlib (`net/url`, `sort`, `strconv`, `strings`, `reflect`), `html/template`, `github.com/stretchr/testify` for asserts.

**Spec:** `docs/superpowers/specs/2026-08-12-login-locale-design.md`

## Global Constraints

- **Locale-koder:** nøyaktig `nb`, `en`, `de`. Fallback er `en`.
- **Ingen nye avhengigheter.** `internal/i18n` bruker bare stdlib — ikke `golang.org/x/text`.
- **Norske kommentarer, engelske identifiers.** Kommentarer forklarer WHY, ikke WHAT.
- **Ingen `Co-Authored-By:`-trailers** i commit-meldinger.
- **Commit-stil:** imperativ, `type(scope): beskrivelse`.
- **`gofmt -l .` og `go vet ./...` skal være tomme/rene før hver commit.**
- **Test-kommando:** `CGO_ENABLED=0 go test ./...` (prosjektet er CGO-fritt).
- **Ingen migrasjon, ingen `make sqlc`.** `services`-tabellen røres ikke.
- **`go vet` og format-strenger:** bruk `strings.ReplaceAll` med `{link}`-placeholder, aldri `fmt.Sprintf` med en ikke-konstant format-streng (vet-feil i Go 1.24+).
- **Admin-panelet forblir norsk.** `internal/admin/*` og `templates/admin/*` skal ikke oversettes.

---

### Task 1: `internal/i18n` — katalogen

Dette er ren data plus ett oppslag. Ingen locale-deteksjon her — den kommer i Task 2.

**Files:**
- Create: `internal/i18n/i18n.go`
- Create: `internal/i18n/catalog.go`
- Test: `internal/i18n/i18n_test.go`

**Interfaces:**
- Consumes: ingenting.
- Produces: `i18n.Strings` (struct, feltnavn nedenfor), `i18n.Get(locale string) Strings`, `i18n.Fallback` (konstant `"en"`), og pakke-intern `catalog map[string]Strings`.

- [ ] **Step 1: Write the failing test**

Create `internal/i18n/i18n_test.go`:

```go
package i18n

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCatalogComplete er sikkerhetsnettet mot halvferdige språk: legger noen
// til et felt i Strings uten å oversette det, feiler denne i stedet for at
// login-siden viser blankt i prod.
func TestCatalogComplete(t *testing.T) {
	for _, locale := range []string{"en", "nb", "de"} {
		s, ok := catalog[locale]
		require.True(t, ok, "locale %s mangler i katalogen", locale)

		v := reflect.ValueOf(s)
		typ := v.Type()
		for i := 0; i < typ.NumField(); i++ {
			assert.NotEmpty(t, v.Field(i).String(),
				"locale %s mangler oversettelse for felt %s", locale, typ.Field(i).Name)
		}
	}
}

// TestCatalogHasNoExtraLocales fanger en locale som er lagt til i katalogen
// men ikke i supported-listen (Task 2) eller i språkvelgeren.
func TestCatalogHasNoExtraLocales(t *testing.T) {
	assert.Len(t, catalog, 3)
}

func TestMailBodyHasOnePlaceholder(t *testing.T) {
	for locale, s := range catalog {
		assert.Equal(t, 1, strings.Count(s.MailBody, "{link}"),
			"locale %s: MailBody må ha nøyaktig én {link}", locale)
		assert.NotContains(t, s.MailBody, "%s",
			"locale %s: bruk {link}, ikke %%s — go vet flagger ikke-konstante format-strenger", locale)
	}
}

func TestGet(t *testing.T) {
	assert.Equal(t, "Fortsett med Google", Get("nb").ContinueWithGoogle)
	assert.Equal(t, "Mit Google fortfahren", Get("de").ContinueWithGoogle)
	assert.Equal(t, "Continue with Google", Get("en").ContinueWithGoogle)
}

func TestGet_UnknownLocaleFallsBackToEnglish(t *testing.T) {
	assert.Equal(t, catalog[Fallback], Get("fr"))
	assert.Equal(t, catalog[Fallback], Get(""))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/i18n/...`
Expected: FAIL — pakken finnes ikke ennå (`no Go files in .../internal/i18n` eller `undefined: catalog`).

- [ ] **Step 3: Write `internal/i18n/i18n.go`**

```go
// Package i18n holder oversettelsene for de bruker-vendte login-sidene og
// magic-link-e-posten. Bevisst uten avhengigheter utover stdlib:
// Accept-Language-parsing er ~40 linjer, og det er billigere enn å dra
// golang.org/x/text inn i en binær som skal være liten og CGO-fri.
package i18n

// Fallback brukes når nettleseren ikke ber om et språk vi har.
const Fallback = "en"

// Strings er alle oversatte tekster for én locale.
//
// Flat struct framfor map[string]string er et bevisst valg: en skrivefeil i
// en template ({{.T.Feilnavn}}) gir render-feil, mens et map-oppslag ville
// gitt en stille tom streng i prod.
type Strings struct {
	// Felles for begge sidene
	SignIn              string
	EmailPlaceholder    string
	PasswordPlaceholder string
	Or                  string

	// login.html
	ContinueWithGoogle    string
	ContinueWithMicrosoft string
	SignInWithEmailLink   string

	// magic-login.html
	MagicPageTitle  string
	MagicSubmit     string
	MagicSending    string
	MagicCheckInbox string
	// MagicSentToBefore og MagicSentToAfter omslutter e-postadressen som
	// JS setter inn i <span id="confirm-email">. Delt i to fordi tysk
	// plasserer verbet etter objektet: "… an <e-post> gesendet."
	MagicSentToBefore string
	MagicSentToAfter  string
	MagicValidMinutes string
	BackToSignIn      string

	// Feilkoder fra ?error=
	ErrAccessDenied    string
	ErrInvalidRedirect string
	ErrExpiredLink     string
	ErrTooManyRequests string

	// Magic-link-e-post. MailBody har nøyaktig én {link}-placeholder.
	MailSubject string
	MailBody    string
}

// Get returnerer katalogen for locale, eller Fallback-katalogen ved ukjent
// locale. Kallere trenger derfor ikke sjekke om locale er støttet.
func Get(locale string) Strings {
	if s, ok := catalog[locale]; ok {
		return s
	}
	return catalog[Fallback]
}
```

- [ ] **Step 4: Write `internal/i18n/catalog.go`**

Egen fil så oversettelses-endringer ikke rører logikken.

```go
package i18n

// catalog er oversettelsene. Alle locales må ha alle felt utfylt —
// TestCatalogComplete håndhever det.
var catalog = map[string]Strings{
	"en": {
		SignIn:              "Sign in",
		EmailPlaceholder:    "Email address",
		PasswordPlaceholder: "Password",
		Or:                  "or",

		ContinueWithGoogle:    "Continue with Google",
		ContinueWithMicrosoft: "Continue with Microsoft",
		SignInWithEmailLink:   "Sign in with an email link",

		MagicPageTitle:    "Email sign-in",
		MagicSubmit:       "Send sign-in link",
		MagicSending:      "Sending…",
		MagicCheckInbox:   "Check your inbox",
		MagicSentToBefore: "We've sent a sign-in link to",
		MagicSentToAfter:  ". Click the link to sign in.",
		MagicValidMinutes: "The link is valid for 15 minutes.",
		BackToSignIn:      "Back to sign-in",

		ErrAccessDenied:    "Access denied.",
		ErrInvalidRedirect: "Invalid return address. Please start the sign-in again.",
		ErrExpiredLink:     "The link has expired or has already been used. Please try again.",
		ErrTooManyRequests: "Too many requests. Please wait a few minutes and try again.",

		MailSubject: "Your sign-in link",
		MailBody:    "Hello!\n\nClick to sign in (valid for 15 minutes):\n\n{link}\n\nIf you didn't request this, you can ignore this email.\n",
	},

	"nb": {
		SignIn:              "Logg inn",
		EmailPlaceholder:    "E-postadresse",
		PasswordPlaceholder: "Passord",
		Or:                  "eller",

		ContinueWithGoogle:    "Fortsett med Google",
		ContinueWithMicrosoft: "Fortsett med Microsoft",
		SignInWithEmailLink:   "Logg inn med e-postlenke",

		MagicPageTitle:    "E-postinnlogging",
		MagicSubmit:       "Send innloggingslenke",
		MagicSending:      "Sender…",
		MagicCheckInbox:   "Sjekk innboksen din",
		MagicSentToBefore: "Vi har sendt en innloggingslenke til",
		MagicSentToAfter:  ". Klikk på lenken for å logge inn.",
		MagicValidMinutes: "Lenken er gyldig i 15 minutter.",
		BackToSignIn:      "Tilbake til innlogging",

		ErrAccessDenied:    "Tilgang nektet.",
		ErrInvalidRedirect: "Ugyldig retur-adresse. Start innloggingen på nytt.",
		ErrExpiredLink:     "Lenken er utløpt eller allerede brukt. Prøv igjen.",
		ErrTooManyRequests: "For mange forespørsler. Vent noen minutter og prøv igjen.",

		MailSubject: "Din innloggingslenke",
		MailBody:    "Hei!\n\nKlikk for å logge inn (gyldig 15 min):\n\n{link}\n\nHvis du ikke ba om dette, ignorer denne e-posten.\n",
	},

	"de": {
		SignIn:              "Anmelden",
		EmailPlaceholder:    "E-Mail-Adresse",
		PasswordPlaceholder: "Passwort",
		Or:                  "oder",

		ContinueWithGoogle:    "Mit Google fortfahren",
		ContinueWithMicrosoft: "Mit Microsoft fortfahren",
		SignInWithEmailLink:   "Mit E-Mail-Link anmelden",

		MagicPageTitle:    "E-Mail-Anmeldung",
		MagicSubmit:       "Anmeldelink senden",
		MagicSending:      "Wird gesendet…",
		MagicCheckInbox:   "Prüfen Sie Ihren E-Mail-Eingang",
		MagicSentToBefore: "Wir haben einen Anmeldelink an",
		MagicSentToAfter:  " gesendet. Klicken Sie auf den Link, um sich anzumelden.",
		MagicValidMinutes: "Der Link ist 15 Minuten gültig.",
		BackToSignIn:      "Zurück zur Anmeldung",

		ErrAccessDenied:    "Zugriff verweigert.",
		ErrInvalidRedirect: "Ungültige Rücksprungadresse. Bitte starten Sie die Anmeldung neu.",
		ErrExpiredLink:     "Der Link ist abgelaufen oder wurde bereits verwendet. Bitte versuchen Sie es erneut.",
		ErrTooManyRequests: "Zu viele Anfragen. Bitte warten Sie einige Minuten und versuchen Sie es erneut.",

		MailSubject: "Ihr Anmeldelink",
		MailBody:    "Hallo!\n\nKlicken Sie, um sich anzumelden (15 Minuten gültig):\n\n{link}\n\nFalls Sie dies nicht angefordert haben, ignorieren Sie diese E-Mail.\n",
	},
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/i18n/... -v`
Expected: PASS — `TestCatalogComplete`, `TestCatalogHasNoExtraLocales`, `TestMailBodyHasOnePlaceholder`, `TestGet`, `TestGet_UnknownLocaleFallsBackToEnglish`.

- [ ] **Step 6: Verify formatting and vet**

Run: `gofmt -l internal/i18n && go vet ./internal/i18n/...`
Expected: ingen output fra `gofmt`, ingen funn fra `go vet`.

- [ ] **Step 7: Commit**

```bash
git add internal/i18n/
git commit -m "feat(i18n): katalog med norsk, engelsk og tysk"
```

---

### Task 2: locale-deteksjon

`?lang=` og `Accept-Language` → én av `nb`/`en`/`de`.

**Files:**
- Modify: `internal/i18n/i18n.go` (legg til nederst)
- Test: `internal/i18n/resolve_test.go`

**Interfaces:**
- Consumes: `Fallback` og `catalog` fra Task 1.
- Produces: `i18n.Resolve(langParam, acceptLanguage string) string`, `i18n.FromRequest(r *http.Request) string`, og pakke-intern `supported []string` (rekkefølge `{"nb", "en", "de"}` — brukes som visningsrekkefølge i Task 3) og `normalize(tag string) string`.

- [ ] **Step 1: Write the failing test**

Create `internal/i18n/resolve_test.go`:

```go
package i18n

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolve(t *testing.T) {
	tests := []struct {
		name   string
		lang   string
		accept string
		want   string
	}{
		{"tom request faller til engelsk", "", "", "en"},
		{"lang-param vinner over header", "de", "nb-NO,nb;q=0.9", "de"},
		{"lang-param er case-insensitiv", "DE", "", "de"},
		{"lang-param tåler whitespace", " nb ", "", "nb"},
		{"ustøttet lang-param faller videre til header", "fr", "de-DE,de;q=0.9", "de"},
		{"ustøttet lang og header faller til engelsk", "fr", "fr-FR,fr;q=0.9", "en"},
		{"region-subtag strippes", "", "de-AT", "de"},
		{"underscore-variant strippes", "", "de_DE", "de"},
		{"nb-NO gir norsk", "", "nb-NO,nb;q=0.9,en;q=0.8", "nb"},
		{"no gir norsk", "", "no", "nb"},
		{"nn gir norsk", "", "nn-NO", "nb"},
		{"q-vekt styrer rekkefølge, ikke posisjon", "", "en;q=0.1,de;q=0.9", "de"},
		{"manglende q betyr full vekt", "", "de,en;q=0.9", "de"},
		{"ugyldig q diskvalifiserer alternativet", "", "de;q=høy,en;q=0.5", "en"},
		{"q=0 diskvalifiserer alternativet", "", "de;q=0,en;q=0.5", "en"},
		{"ukjent språk hoppes over", "", "fr,de;q=0.5", "de"},
		{"lik q beholder rekkefølgen i headeren", "", "de;q=0.5,en;q=0.5", "de"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, Resolve(tc.lang, tc.accept))
		})
	}
}

func TestFromRequest_LangParamWins(t *testing.T) {
	r := httptest.NewRequest("GET", "/login?service=spekto&lang=de", nil)
	r.Header.Set("Accept-Language", "nb-NO,nb;q=0.9")
	assert.Equal(t, "de", FromRequest(r))
}

func TestFromRequest_FallsBackToHeader(t *testing.T) {
	r := httptest.NewRequest("GET", "/login?service=spekto", nil)
	r.Header.Set("Accept-Language", "nb-NO,nb;q=0.9")
	assert.Equal(t, "nb", FromRequest(r))
}

func TestFromRequest_NoSignalsGivesEnglish(t *testing.T) {
	r := httptest.NewRequest("GET", "/login", nil)
	assert.Equal(t, "en", FromRequest(r))
}

// supported må matche katalogen, ellers får vi en språkvelger som peker på
// en locale uten oversettelser.
func TestSupportedMatchesCatalog(t *testing.T) {
	assert.Len(t, supported, len(catalog))
	for _, loc := range supported {
		_, ok := catalog[loc]
		assert.True(t, ok, "supported inneholder %s som ikke finnes i katalogen", loc)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/i18n/...`
Expected: FAIL — `undefined: Resolve`, `undefined: FromRequest`, `undefined: supported`.

- [ ] **Step 3: Add detection to `internal/i18n/i18n.go`**

Legg til imports `net/http`, `sort`, `strconv`, `strings` og følgende nederst i filen:

```go
// supported er locale-kodene vi har oversettelser for, i den rekkefølgen
// språkvelgeren skal vise dem.
var supported = []string{"nb", "en", "de"}

// normalize gjør en BCP47-tag om til en av våre locale-koder, eller "" hvis
// vi ikke har språket. Norsk sendes som nb, nn eller no avhengig av nettleser
// og operativsystem, så alle tre mappes til nb.
func normalize(tag string) string {
	tag = strings.ToLower(strings.TrimSpace(tag))
	if i := strings.IndexAny(tag, "-_"); i >= 0 {
		tag = tag[:i]
	}
	switch tag {
	case "nb", "nn", "no":
		return "nb"
	case "en":
		return "en"
	case "de":
		return "de"
	}
	return ""
}

// Resolve velger locale. En eksplisitt lang-param vinner over nettleserens
// preferanse, men en ustøttet lang-param avbryter ikke kjeden — den faller
// videre til Accept-Language framfor å tvinge fallback.
func Resolve(langParam, acceptLanguage string) string {
	if loc := normalize(langParam); loc != "" {
		return loc
	}
	if loc := fromAcceptLanguage(acceptLanguage); loc != "" {
		return loc
	}
	return Fallback
}

// FromRequest er wrapperen handlerne bruker.
func FromRequest(r *http.Request) string {
	return Resolve(r.URL.Query().Get("lang"), r.Header.Get("Accept-Language"))
}

// fromAcceptLanguage plukker det høyest vektede språket vi støtter, eller ""
// hvis ingen av alternativene finnes i katalogen.
func fromAcceptLanguage(header string) string {
	type candidate struct {
		locale string
		weight float64
	}
	var candidates []candidate

	for _, part := range strings.Split(header, ",") {
		fields := strings.Split(part, ";")
		locale := normalize(fields[0])
		if locale == "" {
			continue
		}
		weight := 1.0
		for _, f := range fields[1:] {
			f = strings.TrimSpace(f)
			if !strings.HasPrefix(f, "q=") {
				continue
			}
			parsed, err := strconv.ParseFloat(f[2:], 64)
			if err != nil {
				// Ugyldig q diskvalifiserer alternativet framfor å gi det
				// full vekt — en klient som sender søppel skal ikke kunne
				// overstyre et velformet alternativ lenger ned i listen.
				weight = 0
				break
			}
			weight = parsed
		}
		if weight > 0 {
			candidates = append(candidates, candidate{locale, weight})
		}
	}

	if len(candidates) == 0 {
		return ""
	}
	// Stabil sortering, så lik q beholder rekkefølgen klienten sendte.
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].weight > candidates[j].weight
	})
	return candidates[0].locale
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/i18n/... -v`
Expected: PASS, inkludert alle 17 subtester i `TestResolve`.

- [ ] **Step 5: Verify formatting and vet**

Run: `gofmt -l internal/i18n && go vet ./internal/i18n/...`
Expected: ingen output.

- [ ] **Step 6: Commit**

```bash
git add internal/i18n/
git commit -m "feat(i18n): locale-deteksjon fra lang-param og Accept-Language"
```

---

### Task 3: språkvelger-lenker

**Files:**
- Modify: `internal/i18n/i18n.go` (legg til nederst)
- Test: `internal/i18n/links_test.go`

**Interfaces:**
- Consumes: `supported` fra Task 2.
- Produces: `i18n.Link` (felt `Code`, `Label`, `Name`, `Href`, `Active` — alle `string` unntatt `Active bool`) og `i18n.Links(active string, u *url.URL) []Link`.

- [ ] **Step 1: Write the failing test**

Create `internal/i18n/links_test.go`:

```go
package i18n

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinks_PreservesQueryAndSetsLang(t *testing.T) {
	u, err := url.Parse("/login?service=spekto&redirect_uri=https%3A%2F%2Fspekto.live%2Fcb&lang=nb")
	require.NoError(t, err)

	links := Links("nb", u)
	require.Len(t, links, 3)

	byCode := map[string]Link{}
	for _, l := range links {
		byCode[l.Code] = l
	}

	de, ok := byCode["de"]
	require.True(t, ok)
	assert.False(t, de.Active)
	assert.Equal(t, "DE", de.Label)
	assert.Equal(t, "Deutsch", de.Name)

	parsed, err := url.Parse(de.Href)
	require.NoError(t, err)
	assert.Equal(t, "/login", parsed.Path)
	assert.Empty(t, parsed.Host, "href skal være path-relativ så host ikke havner i markup")
	assert.Equal(t, "de", parsed.Query().Get("lang"), "lang skal overskrives, ikke dupliseres")
	assert.Equal(t, "spekto", parsed.Query().Get("service"))
	assert.Equal(t, "https://spekto.live/cb", parsed.Query().Get("redirect_uri"))

	assert.True(t, byCode["nb"].Active, "aktivt språk skal markeres")
	assert.False(t, byCode["en"].Active)
}

func TestLinks_NoExistingQuery(t *testing.T) {
	u, err := url.Parse("/magic-login")
	require.NoError(t, err)

	links := Links("en", u)
	require.Len(t, links, 3)
	// supported-rekkefølgen er nb, en, de.
	assert.Equal(t, "nb", links[0].Code)
	assert.Equal(t, "/magic-login?lang=nb", links[0].Href)
	assert.True(t, links[1].Active)
}

func TestLinks_AllHaveLabelAndName(t *testing.T) {
	u, err := url.Parse("/login")
	require.NoError(t, err)

	for _, l := range Links("en", u) {
		assert.NotEmpty(t, l.Label, "locale %s mangler Label", l.Code)
		assert.NotEmpty(t, l.Name, "locale %s mangler Name", l.Code)
		assert.NotEmpty(t, l.Href, "locale %s mangler Href", l.Code)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/i18n/...`
Expected: FAIL — `undefined: Links`, `undefined: Link`.

- [ ] **Step 3: Add to `internal/i18n/i18n.go`**

Legg til import `net/url` og følgende nederst:

```go
// Link er ett alternativ i språkvelgeren på login-sidene.
type Link struct {
	Code   string // "nb" — brukes som lang- og hreflang-attributt
	Label  string // "NO" — teksten som vises
	Name   string // "Norsk" — title/aria-label for skjermlesere
	Href   string // path + query med lang satt
	Active bool
}

// display holder visningsnavnene. Hvert språk skriver sitt eget navn på sitt
// eget språk — en tysk bruker leter etter "Deutsch", ikke "German".
var display = map[string]struct{ Label, Name string }{
	"nb": {"NO", "Norsk"},
	"en": {"EN", "English"},
	"de": {"DE", "Deutsch"},
}

// Links bygger språkvelgeren for gjeldende URL. Href-ene er path-relative så
// host aldri havner i markup, og eksisterende query-params (service,
// redirect_uri) overlever språkbyttet.
func Links(active string, u *url.URL) []Link {
	out := make([]Link, 0, len(supported))
	for _, code := range supported {
		q := u.Query()
		q.Set("lang", code)
		out = append(out, Link{
			Code:   code,
			Label:  display[code].Label,
			Name:   display[code].Name,
			Href:   u.Path + "?" + q.Encode(),
			Active: code == active,
		})
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/i18n/... -v`
Expected: PASS.

- [ ] **Step 5: Verify formatting and vet**

Run: `gofmt -l internal/i18n && go vet ./internal/i18n/...`
Expected: ingen output.

- [ ] **Step 6: Commit**

```bash
git add internal/i18n/
git commit -m "feat(i18n): språkvelger-lenker som bevarer query-params"
```

---

### Task 4: `/login` oversatt

**Files:**
- Modify: `internal/auth/login.go` (`LoginPageData` linje 13-24, `ServeLogin` linje 57-90)
- Modify: `templates/login.html`
- Test: `internal/auth/login_render_test.go`

**Interfaces:**
- Consumes: `i18n.Strings`, `i18n.Get`, `i18n.FromRequest`, `i18n.Link`, `i18n.Links` fra Task 1-3. Bruker eksisterende `buildBgCSS(theme string, bgImage, bgCss *string) (template.CSS, template.CSS)` i `login.go`.
- Produces: `LoginPageData` med tre nye felt — `Locale string`, `T i18n.Strings`, `Languages []i18n.Link`. Task 5 gjenbruker samme struct for `magic-login.html`, og gjenbruker `testLoginService` fra testfilen.

- [ ] **Step 1: Write the failing test**

Create `internal/auth/login_render_test.go`:

```go
package auth

import (
	"html/template"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/i18n"
)

// testLoginService har alle fire innloggingsmetoder på, slik at rendringen
// treffer hver gren i templaten og ingen oversatt streng blir stående
// uprøvd bak en {{if}}.
func testLoginService(theme string) *gen.Service {
	tagline := "Test-tjeneste"
	return &gen.Service{
		ID:            "test",
		DisplayName:   "Testify",
		Tagline:       &tagline,
		Domain:        "test.local",
		CallbackUrl:   "https://test.local/callback",
		Theme:         theme,
		AccentColor:   "#2563EB",
		EmailFromName: "Test",
		AuthGoogle:    1,
		AuthMicrosoft: 1,
		AuthMagicLink: 1,
		AuthPassword:  1,
		JwtCookieName: "auth_token",
		AccessTokenTtl: "PT15M",
		Active:        1,
	}
}

// testPageData bygger template-data slik ServeLogin gjør det.
func testPageData(t *testing.T, theme, locale, rawURL string) LoginPageData {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)

	svc := testLoginService(theme)
	bodyCss, beforeCss := buildBgCSS(svc.Theme, svc.BgImage, svc.BgCss)
	return LoginPageData{
		Service:     svc,
		BodyBgCSS:   bodyCss,
		BeforeBgCSS: beforeCss,
		Locale:      locale,
		T:           i18n.Get(locale),
		Languages:   i18n.Links(locale, u),
	}
}

// TestLoginTemplate_RendersInAllLocales fanger feltnavn-typo i templaten —
// den ene feilklassen struct-katalogen ikke fanger ved kompilering.
func TestLoginTemplate_RendersInAllLocales(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)

	want := map[string]string{
		"en": "Continue with Google",
		"nb": "Fortsett med Google",
		"de": "Mit Google fortfahren",
	}

	for _, theme := range []string{"light", "dark"} {
		for _, locale := range []string{"en", "nb", "de"} {
			t.Run(theme+"/"+locale, func(t *testing.T) {
				data := testPageData(t, theme, locale, "/login?service=test")

				var out strings.Builder
				require.NoError(t, tmpl.ExecuteTemplate(&out, "login.html", data))

				html := out.String()
				assert.Contains(t, html, want[locale])
				assert.Contains(t, html, `<html lang="`+locale+`">`)
				// Magic-link-knappen må bære språket videre. Sjekk hele
				// href-en, ikke bare "lang=<locale>" — den strengen finnes
				// i språkvelgeren uansett locale og ville gjort testen blind.
				assert.Contains(t, html, "/magic-login?service=test&amp;lang="+locale)
			})
		}
	}
}

func TestLoginTemplate_ShowsLanguageSwitcher(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)

	data := testPageData(t, "light", "de", "/login?service=test")
	var out strings.Builder
	require.NoError(t, tmpl.ExecuteTemplate(&out, "login.html", data))

	html := out.String()
	// Aktivt språk vises uten lenke, de to andre som lenker.
	assert.Contains(t, html, ">DE<")
	assert.Contains(t, html, "Norsk")
	assert.Contains(t, html, "English")
	assert.Contains(t, html, "lang=nb")
	assert.Contains(t, html, "lang=en")
}

func TestLoginTemplate_TranslatesErrorCodes(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)

	data := testPageData(t, "light", "de", "/login?service=test")
	data.Error = "access_denied"

	var out strings.Builder
	require.NoError(t, tmpl.ExecuteTemplate(&out, "login.html", data))
	assert.Contains(t, out.String(), "Zugriff verweigert.")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/auth/ -run TestLoginTemplate`
Expected: FAIL — `unknown field Locale in struct literal of type LoginPageData`.

- [ ] **Step 3: Add the fields to `internal/auth/login.go`**

Legg til import `"github.com/zral/kauth-go/internal/i18n"` og utvid structen:

```go
// LoginPageData er template-data for login.html og magic-login.html.
type LoginPageData struct {
	Service     *gen.Service
	LogoHTML    template.HTML // konvertert fra Service.LogoHtml — rå HTML, ikke escaped
	RedirectURI string
	Error       string
	// BodyBgCSS er ferdig-beregnet CSS background-verdi for body-elementet.
	// Brukes i <style>-blokken der Go html/template blokkerer dynamisk url()-konstruksjon.
	// Trust boundary: verdien er sammensatt fra DB-felter (BgCss, BgImage) med fast /static/-prefix.
	BodyBgCSS template.CSS
	// BeforeBgCSS er ferdig-beregnet CSS background-verdi for body::before (mørkt tema).
	BeforeBgCSS template.CSS
	// Locale er valgt språk (nb/en/de) — brukes som lang-attributt og for å
	// bære språket videre i lenker ut av siden.
	Locale string
	// T er de oversatte tekstene for Locale.
	T i18n.Strings
	// Languages er alternativene i språkvelgeren.
	Languages []i18n.Link
}
```

- [ ] **Step 4: Wire it up in `ServeLogin`**

Erstatt `data := LoginPageData{...}`-blokken (linje 77-84) med:

```go
	locale := i18n.FromRequest(r)
	bodyCss, beforeCss := buildBgCSS(svc.Theme, svc.BgImage, svc.BgCss)
	data := LoginPageData{
		Service:     svc,
		LogoHTML:    logoHTML,
		RedirectURI: redirectURI,
		Error:       r.URL.Query().Get("error"),
		BodyBgCSS:   bodyCss,
		BeforeBgCSS: beforeCss,
		Locale:      locale,
		T:           i18n.Get(locale),
		Languages:   i18n.Links(locale, r.URL),
	}
```

Den eksisterende `bodyCss, beforeCss := buildBgCSS(...)` på linje 76 skal fjernes, ikke dupliseres.

- [ ] **Step 5: Translate `templates/login.html`**

Ni endringer:

1. Linje 2: `<html lang="no">` → `<html lang="{{.Locale}}">`
2. Linje 6: `<title>Logg inn – {{.Service.DisplayName}}</title>` → `<title>{{.T.SignIn}} – {{.Service.DisplayName}}</title>`
3. Feilblokken (linje 109-112) → oversatte tekster:

```html
            {{if eq .Error "access_denied"}}{{.T.ErrAccessDenied}}
            {{else if eq .Error "invalid_redirect"}}{{.T.ErrInvalidRedirect}}
            {{else}}{{.Error}}
            {{end}}
```

4. Linje 124: `Fortsett med Google` → `{{.T.ContinueWithGoogle}}`
5. Linje 136: `Fortsett med Microsoft` → `{{.T.ContinueWithMicrosoft}}`
6. Linje 141 og 154: `<div class="divider">eller</div>` → `<div class="divider">{{.T.Or}}</div>` (begge stedene)
7. Linje 142: magic-knappens href bærer språket videre:

```html
        <a id="magic-btn" href="/magic-login?service={{.Service.ID}}&amp;lang={{.Locale}}" class="btn-social">
```

8. Linje 149: `Logg inn med e-postlenke` → `{{.T.SignInWithEmailLink}}`
9. Passord-formen (linje 157, 163, 175): `placeholder="E-postadresse"` → `placeholder="{{.T.EmailPlaceholder}}"`, `placeholder="Passord"` → `placeholder="{{.T.PasswordPlaceholder}}"`, knappeteksten `Logg inn` → `{{.T.SignIn}}`

- [ ] **Step 6: Add the language switcher to `templates/login.html`**

CSS — legg til i `<style>`-blokken rett før `.msg-error` (linje 86). `.card` har allerede `position: relative`, så absolutt posisjonering under kortet fungerer:

```css
        .lang {
            position: absolute; left: 0; right: 0; top: 100%;
            margin-top: .75rem; text-align: center;
            font-size: .8rem; letter-spacing: .02em;
        }
        .lang a, .lang span { text-decoration: none; padding: 0 .2rem; }
        {{if eq .Service.Theme "dark"}}
        .lang a { color: #52525B; }
        .lang a:hover { color: #A1A1AA; }
        .lang .active { color: #A1A1AA; font-weight: 600; }
        .lang .sep { color: #3F3F46; }
        {{else}}
        .lang a { color: #475569; text-shadow: 0 1px 3px rgba(255,255,255,.9); }
        .lang a:hover { color: #0f172a; }
        .lang .active { color: #0f172a; font-weight: 600; text-shadow: 0 1px 3px rgba(255,255,255,.9); }
        .lang .sep { color: #94a3b8; }
        {{end}}
```

Markup — legg til rett før `</div>` som lukker `.card` (etter passord-formens `{{end}}`, linje 178):

```html
        <nav class="lang">
            {{range $i, $l := .Languages}}{{if $i}}<span class="sep">·</span>{{end}}{{if $l.Active}}<span class="active" lang="{{$l.Code}}" title="{{$l.Name}}">{{$l.Label}}</span>{{else}}<a href="{{$l.Href}}" hreflang="{{$l.Code}}" title="{{$l.Name}}">{{$l.Label}}</a>{{end}}{{end}}
        </nav>
```

`{{range}}` og `{{if}}` står på én linje for å unngå whitespace mellom skilletegn og labels.

- [ ] **Step 7: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/auth/ -run TestLoginTemplate -v`
Expected: PASS — 6 subtester i `TestLoginTemplate_RendersInAllLocales`, plus switcher- og error-testene.

- [ ] **Step 8: Run the full suite, formatting and vet**

Run: `CGO_ENABLED=0 go test ./... && gofmt -l . && go vet ./...`
Expected: alle pakker PASS, ingen output fra `gofmt`, ingen funn fra `go vet`.

- [ ] **Step 9: Commit**

```bash
git add internal/auth/login.go internal/auth/login_render_test.go templates/login.html
git commit -m "feat(auth): oversatt login-side med språkvelger"
```

---

### Task 5: `/magic-login` og magic-link-e-posten oversatt

**Files:**
- Modify: `internal/mail/mail.go:16` (`SendMagicLink`)
- Modify: `internal/admin/auth.go:132` (kall-sted)
- Modify: `internal/auth/magic.go:77-97` (`ShowForm`), `internal/auth/magic.go:146-151` (`RequestLink`)
- Modify: `templates/magic-login.html`
- Modify: `internal/auth/login_render_test.go` (utvid)
- Modify: `CHANGELOG.md`
- Test: `internal/mail/mail_test.go`

**Interfaces:**
- Consumes: `i18n.Get`, `i18n.FromRequest`, `i18n.Links` fra Task 1-3; `LoginPageData` med `Locale`/`T`/`Languages` og testhjelperne `testLoginService`/`testPageData` fra Task 4.
- Produces: `mail.Service.SendMagicLink(to, fromName, linkURL, locale string) error` — signaturen får en fjerde parameter, så begge kall-steder må oppdateres i samme commit.

- [ ] **Step 1: Write the failing test for the mailer**

Create `internal/mail/mail_test.go`:

```go
package mail

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/i18n"
)

// buildMagicBody er den rene tekst-byggingen SendMagicLink gjør. Testet
// direkte fordi SendMagicLink ellers krever en SMTP-server.
func TestBuildMagicBody_ReplacesLink(t *testing.T) {
	link := "https://auth.spekto.live/magic-login/abc123?service=spekto"

	for _, locale := range []string{"en", "nb", "de"} {
		body := buildMagicBody(i18n.Get(locale), link)
		assert.Contains(t, body, link, "locale %s: lenken mangler i brødteksten", locale)
		assert.NotContains(t, body, "{link}", "locale %s: placeholder ikke erstattet", locale)
	}
}

func TestBuildMagicBody_LocalisedText(t *testing.T) {
	link := "https://example.test/x"
	assert.Contains(t, buildMagicBody(i18n.Get("de"), link), "Hallo!")
	assert.Contains(t, buildMagicBody(i18n.Get("nb"), link), "Hei!")
	assert.Contains(t, buildMagicBody(i18n.Get("en"), link), "Hello!")
}

func TestBuildMessage_UsesLocalisedSubject(t *testing.T) {
	msg := buildMessage("from@example.test", "Test", "to@example.test",
		i18n.Get("de").MailSubject, "brødtekst")
	require.True(t, strings.Contains(msg, "Subject: Ihr Anmeldelink"),
		"emnet skal være tysk, fikk:\n%s", msg)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/mail/...`
Expected: FAIL — `undefined: buildMagicBody`.

- [ ] **Step 3: Update `internal/mail/mail.go`**

Legg til import `"github.com/zral/kauth-go/internal/i18n"` og erstatt `SendMagicLink` (linje 16-30):

```go
// SendMagicLink sender innloggingslenken på valgt språk. Ukjent locale
// faller til engelsk via i18n.Get, så kalleren trenger ikke validere.
func (s *Service) SendMagicLink(to, fromName, linkURL, locale string) error {
	t := i18n.Get(locale)
	if s.cfg.SMTPMock {
		fmt.Printf("[MAIL MOCK] To: %s | Fra: %s | Språk: %s | Link: %s\n", to, fromName, locale, linkURL)
		return nil
	}
	msg := buildMessage(s.cfg.SMTPFrom, fromName, to, t.MailSubject, buildMagicBody(t, linkURL))
	addr := fmt.Sprintf("%s:%d", s.cfg.SMTPHost, s.cfg.SMTPPort)
	auth := smtp.PlainAuth("", s.cfg.SMTPUser, s.cfg.SMTPPassword, s.cfg.SMTPHost)
	if s.cfg.SMTPStartTLS {
		return sendSTARTTLS(addr, auth, s.cfg.SMTPHost, s.cfg.SMTPFrom, to, msg)
	}
	return smtp.SendMail(addr, auth, s.cfg.SMTPFrom, []string{to}, []byte(msg))
}

// buildMagicBody setter lenken inn i den oversatte brødteksten.
// Navngitt placeholder framfor %s fordi go vet flagger fmt.Sprintf med
// ikke-konstant format-streng.
func buildMagicBody(t i18n.Strings, linkURL string) string {
	return strings.ReplaceAll(t.MailBody, "{link}", linkURL)
}
```

`strings` er allerede importert i filen (brukes av `buildMessage`).

- [ ] **Step 4: Update both call sites**

`internal/admin/auth.go:132` — admin-panelet er norsk-only:

```go
	// Admin-panelet er norsk-only, så e-posten sendes eksplisitt på norsk.
	if sendErr := h.mailer.SendMagicLink(email, fromName, verifyURL, "nb"); sendErr != nil {
		return sendErr
	}
```

`internal/auth/magic.go` i `RequestLink` — les locale like etter `_ = r.ParseForm()` (linje 108) og bruk det i mailer-kallet (linje 148):

```go
	// Locale leses fra POST-URL-en; magic-login.html legger ?lang= på fetch-kallet.
	locale := i18n.FromRequest(r)
```

```go
	if err := h.mailer.SendMagicLink(email, fromName, link, locale); err != nil {
```

- [ ] **Step 5: Run the mailer tests**

Run: `CGO_ENABLED=0 go test ./internal/mail/... ./internal/admin/... -v`
Expected: PASS.

- [ ] **Step 6: Wire locale into `ShowForm`**

`internal/auth/magic.go` — legg til import `"github.com/zral/kauth-go/internal/i18n"` og erstatt `data := LoginPageData{...}` (linje 88-94):

```go
	locale := i18n.FromRequest(r)
	data := LoginPageData{
		Service:     svc,
		LogoHTML:    logoHTML,
		Error:       r.URL.Query().Get("error"),
		BodyBgCSS:   bodyCss,
		BeforeBgCSS: beforeCss,
		Locale:      locale,
		T:           i18n.Get(locale),
		Languages:   i18n.Links(locale, r.URL),
	}
```

- [ ] **Step 7: Write the failing template test**

Legg til i `internal/auth/login_render_test.go`:

```go
func TestMagicLoginTemplate_RendersInAllLocales(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)

	wantSubmit := map[string]string{
		"en": "Send sign-in link",
		"nb": "Send innloggingslenke",
		"de": "Anmeldelink senden",
	}
	wantInbox := map[string]string{
		"en": "Check your inbox",
		"nb": "Sjekk innboksen din",
		"de": "Prüfen Sie Ihren E-Mail-Eingang",
	}

	for _, theme := range []string{"light", "dark"} {
		for _, locale := range []string{"en", "nb", "de"} {
			t.Run(theme+"/"+locale, func(t *testing.T) {
				data := testPageData(t, theme, locale, "/magic-login?service=test")

				var out strings.Builder
				require.NoError(t, tmpl.ExecuteTemplate(&out, "magic-login.html", data))

				html := out.String()
				assert.Contains(t, html, wantSubmit[locale])
				assert.Contains(t, html, wantInbox[locale])
				assert.Contains(t, html, `<html lang="`+locale+`">`)
				// fetch() må sende språket videre så e-posten blir riktig.
				assert.Contains(t, html, "/magic-login?lang=")
			})
		}
	}
}

// Tysk ordstilling krever at setningen deles rundt e-postadressen:
// "… an <e-post> gesendet." Verbet havner etter objektet.
func TestMagicLoginTemplate_GermanWordOrder(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)

	data := testPageData(t, "light", "de", "/magic-login?service=test")
	var out strings.Builder
	require.NoError(t, tmpl.ExecuteTemplate(&out, "magic-login.html", data))

	html := out.String()
	before := strings.Index(html, "Wir haben einen Anmeldelink an")
	span := strings.Index(html, `id="confirm-email"`)
	after := strings.Index(html, "gesendet.")
	require.NotEqual(t, -1, before)
	require.NotEqual(t, -1, span)
	require.NotEqual(t, -1, after)
	assert.Less(t, before, span, "prefiks skal komme før e-postadressen")
	assert.Less(t, span, after, "verbet skal komme etter e-postadressen")
}

func TestMagicLoginTemplate_TranslatesErrorCodes(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)

	data := testPageData(t, "light", "en", "/magic-login?service=test")
	data.Error = "rate"

	var out strings.Builder
	require.NoError(t, tmpl.ExecuteTemplate(&out, "magic-login.html", data))
	assert.Contains(t, out.String(), "Too many requests.")
}
```

- [ ] **Step 8: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/auth/ -run TestMagicLoginTemplate`
Expected: FAIL — templaten har fortsatt norsk hardkodet, så `Send sign-in link` og `Anmeldelink senden` mangler i output.

- [ ] **Step 9: Translate `templates/magic-login.html`**

1. Linje 2: `<html lang="no">` → `<html lang="{{.Locale}}">`
2. Linje 6: `<title>E-postinnlogging – {{.Service.DisplayName}}</title>` → `<title>{{.T.MagicPageTitle}} – {{.Service.DisplayName}}</title>`
3. Undertittelen: `<p>Logg inn med e-postlenke</p>` → `<p>{{.T.SignInWithEmailLink}}</p>`
4. Feilblokken:

```html
            {{if eq .Error "expired"}}{{.T.ErrExpiredLink}}
            {{else if eq .Error "rate"}}{{.T.ErrTooManyRequests}}
            {{else if eq .Error "invalid_redirect"}}{{.T.ErrInvalidRedirect}}
            {{else}}{{.Error}}
            {{end}}
```

5. Formen:

```html
            <input type="email" name="email" placeholder="{{.T.EmailPlaceholder}}" autofocus required>
            <button type="submit" class="btn" id="submit-btn">{{.T.MagicSubmit}}</button>
```

6. Bekreftelses-blokken — `MagicSentToAfter` limes direkte etter `</span>` uten mellomrom, siden nb/en-varianten begynner med punktum:

```html
            <h2>{{.T.MagicCheckInbox}}</h2>
            <p>{{.T.MagicSentToBefore}}
                <span id="confirm-email" class="email-highlight"></span>{{.T.MagicSentToAfter}}</p>
            <p style="margin-top:.75rem;font-size:.8rem;
                {{if eq .Service.Theme "dark"}}color:#71717A;{{else}}color:#6b7280;{{end}}">
                {{.T.MagicValidMinutes}}</p>
```

7. Tilbake-lenken bærer språket videre:

```html
        <a href="/login?service={{.Service.ID}}&amp;lang={{.Locale}}" class="back" id="back-link">
            {{.T.BackToSignIn}}
        </a>
```

8. Språkvelgeren — samme CSS og markup som i Task 4 Step 6. `.card` har allerede `position: relative` (linje 28), så den absolutte posisjoneringen fungerer uten endringer. CSS-en legges inn i `<style>`-blokken, markupen rett før `</div>` som lukker `.card` — etter tilbake-lenken.

9. JS-blokken — strengene injiseres som et objekt, og `fetch()` bærer språket videre:

```html
    <script>
        var I18N = { sending: {{.T.MagicSending}}, submit: {{.T.MagicSubmit}} };
        var LANG = {{.Locale}};
        (function() {
            var form = document.getElementById('form');
            form.addEventListener('submit', function(e) {
                e.preventDefault();
                var email = form.querySelector('input[name="email"]').value;
                var btn = document.getElementById('submit-btn');
                btn.disabled = true;
                btn.textContent = I18N.sending;
                fetch('/magic-login?lang=' + encodeURIComponent(LANG), {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: 'email=' + encodeURIComponent(email) +
                          '&service=' + encodeURIComponent('{{.Service.ID}}'),
                    credentials: 'include'
                }).then(function() {
                    form.style.display = 'none';
                    document.getElementById('confirm').style.display = 'block';
                    document.getElementById('confirm-email').textContent = email;
                    document.getElementById('back-link').style.display = 'none';
                }).catch(function() {
                    btn.disabled = false;
                    btn.textContent = I18N.submit;
                });
            });
        })();
    </script>
```

`html/template` quoter og escaper `{{.T.MagicSending}}` og `{{.Locale}}` selv i JS-kontekst — ikke legg til anførselstegn manuelt.

- [ ] **Step 10: Run tests to verify they pass**

Run: `CGO_ENABLED=0 go test ./internal/auth/ -run 'TestLoginTemplate|TestMagicLoginTemplate' -v`
Expected: PASS.

- [ ] **Step 11: Update `CHANGELOG.md`**

Legg til under `## [Unreleased]` → `### Added`:

```markdown
- Login-sidene (`/login`, `/magic-login`) og magic-link-e-posten finnes på norsk, engelsk og tysk. Språk velges fra `?lang=` eller nettleserens `Accept-Language`, med engelsk som fallback. Diskret språkvelger nederst på sidene. Admin-panelet er fortsatt norsk-only.
```

- [ ] **Step 12: Run the full suite, formatting and vet**

Run: `CGO_ENABLED=0 go test ./... && gofmt -l . && go vet ./...`
Expected: alle pakker PASS, ingen output fra `gofmt`, ingen funn fra `go vet`.

- [ ] **Step 13: Verify the build**

Run: `make build`
Expected: `bin/kauth` bygges uten feil.

- [ ] **Step 14: Commit**

```bash
git add internal/mail/ internal/admin/auth.go internal/auth/magic.go \
        internal/auth/login_render_test.go templates/magic-login.html CHANGELOG.md
git commit -m "feat(auth): oversatt magic-login-side og innloggingse-post"
```

---

### Task 6: manuell verifisering

Templatene parses ved oppstart og leses fra disk, så en render-test i Go fanger ikke feil CSS-posisjonering eller en språkvelger som havner utenfor kortet.

**Files:** ingen — dette er verifisering.

**Interfaces:**
- Consumes: hele funksjonaliteten fra Task 1-5.
- Produces: ingenting.

- [ ] **Step 1: Start serveren lokalt**

```bash
KAUTH_SMTP_MOCK=true KAUTH_INSECURE_COOKIES=true ./bin/kauth
```

- [ ] **Step 2: Sjekk alle tre språk på /login**

Åpne i nettleser og bekreft at tekstene bytter og at språkvelgeren står sentrert under kortet:

- `http://localhost:8080/login?lang=nb`
- `http://localhost:8080/login?lang=en`
- `http://localhost:8080/login?lang=de`

- [ ] **Step 3: Sjekk Accept-Language-deteksjonen**

```bash
curl -s -H 'Accept-Language: de-DE,de;q=0.9,en;q=0.8' http://localhost:8080/login | grep -o '<html lang="[a-z]*"'
curl -s -H 'Accept-Language: fr-FR' http://localhost:8080/login | grep -o '<html lang="[a-z]*"'
curl -s -H 'Accept-Language: nb-NO,nb;q=0.9' http://localhost:8080/login | grep -o '<html lang="[a-z]*"'
```

Expected: `de`, `en`, `nb`.

- [ ] **Step 4: Sjekk at språket overlever klikket til magic-login**

Åpne `http://localhost:8080/login?lang=de`, klikk «Mit E-Mail-Link anmelden», og bekreft at siden fortsatt er tysk — ikke faller tilbake til norsk eller engelsk.

- [ ] **Step 5: Sjekk e-postspråket**

Send inn en e-postadresse på den tyske magic-login-siden. Bekreft i stdout at `[MAIL MOCK]`-linjen viser `Språk: de`, og at bekreftelses-teksten på siden har riktig tysk ordstilling rundt e-postadressen.

- [ ] **Step 6: Sjekk at query-params overlever språkbytte**

Åpne `http://localhost:8080/login?service=<en-tjeneste-id>&redirect_uri=https://example.test/cb&lang=en`, klikk «NO», og bekreft at `service` og `redirect_uri` fortsatt står i URL-en.

- [ ] **Step 7: Sjekk mørkt tema**

Gjenta Step 2 for en tjeneste med `theme = 'dark'` og bekreft at språkvelgeren er lesbar mot mørk bakgrunn.
