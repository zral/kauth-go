---
name: kauth-ux
description: "Designsystem og UX for kauth — login-sider med theming per tjeneste (light/dark, bakgrunn, logo, tagline, i18n nb/en/de) og admin-panelet. Trigger ved endringer i templates/, static/, theming-felter i services, i18n-tekster eller admin-UI."
---

# kauth designsystem (server-rendret Go html/template)

Bruk ALLTID disse reglene for visuell konsistens. Login-siden er det eneste sluttbrukere ser av kauth — den skal se ut som *tjenesten* de er på vei til, ikke som kauth.

## Teknisk stack og konvensjoner

- **Server-rendret:** Go `html/template`, maler i `templates/` parses ved oppstart. Ingen frontend-rammeverk, ingen byggesteg, ingen bundler.
- **CSS:** Inline `<style>`-blokk per mal. Ingen delt stylesheet, ingen Tailwind. Tema-forgreninger skjer med `{{if eq .Service.Theme "dark"}}` i CSS-en.
- **JavaScript:** Minimalt, inline IIFE. Brukes bare der det trengs: videreføring av `redirect_uri` til knappene (login.html) og fetch-innsending med bekreftelsesvisning (magic-login.html). Siden skal fungere uten JS for kjerneflyten.
- **Ikoner:** Inline SVG — offisielle Google- og Microsoft-logoer, konvolutt (stroke-ikon) for magic link. Ingen ikon-CDN.
- **Fonter:** Systemfont-stack (`-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif`). Google Fonts kun som eksplisitt tjenestespesifikt unntak (spekto: DM Sans + Space Grotesk).
- **Statiske filer:** `static/` serves på `/static/`. Bakgrunnsbilder (jpg/webp) refereres fra `services.bg_image` uten prefiks; `buildBgCSS` i `internal/auth/login.go` legger på `/static/`.
- **Sikkerhet i maler:** `html/template` escaper automatisk. Dynamisk CSS går via `template.CSS` (`BodyBgCSS`, `BeforeBgCSS`) som bygges i Go fra DB-felter med fast prefiks — aldri bygg `url()` i malen. `logo_html` er tillitsgrense: kun admin kan sette den.

## Theming per tjeneste (`services`-raden)

| Felt | Effekt |
|------|--------|
| `display_name` | `<h1>` og `<title>` |
| `tagline` | Undertekst under navnet — fallback. Tjenester med oppføring i `internal/i18n/taglines.go` får tagline per språk derfra (`TestTaglinesComplete` krever alle tre språk) |
| `logo_html` | Inline SVG/HTML til venstre for navnet (`.logo-row`, 36×36) |
| `theme` | `light` (default) eller `dark` — styrer hele fargepaletten |
| `bg_image` | Fullskjerms bakgrunnsbilde (`center/cover`) |
| `bg_css` | Flat bakgrunnsfarge/gradient — brukes når bilde ikke er satt; i mørkt tema også som `body::before`-lag |
| `accent_color` | Lagres og redigeres i admin, men **leses ikke av login-malene i dag** — knappefarger er hardkodet per tema. Ny bruk av feltet er en feature, ikke en stilfiks |
| `auth_*` | Hvilke knapper som vises (Google, Microsoft, magic link, legacy-passord) |

Nye theming-felt følger CLAUDE.md-flyten: migrasjon → query → `make sqlc` → `service.Service` → mal. Default må gi uendret utseende for eksisterende tjenester.

## Fargepaletter

### Lyst tema (default)

Kortet er transparent over bakgrunnsbildet; lesbarhet sikres med `text-shadow: 0 1px 3px rgba(255,255,255,.9)` på tekst.

```css
/* Tekst */      #0f172a (primær)  #475569 (sekundær)  #9ca3af (placeholder)
/* Flater */     white (knapper/input)  #f8fafc (hover)
/* Kanter */     #d1d5db  #94a3b8 (hover)
/* Primær */     #1e40af  #1e3a8a (hover)  #3b82f6 (fokusring, 15 % alfa)
/* Feil */       #dc2626 på #fef2f2
/* Radius */     6px
```

### Mørkt tema

Zinc-skala med indigo aksent. `body::before` gir et diffust lysfelt (`rgba(129,140,248,.08)`, `blur(120px)`) eller et dempet `bg_css`-lag.

```css
/* Tekst */      #F4F4F5 (primær)  #A1A1AA (sekundær)  #71717A (muted)
/* Flater */     #18181B (knapper/input)  #27272A (hover)
/* Kanter */     #3F3F46  #71717A (hover)
/* Primær */     #818CF8  #6366F1 (hover)
/* Feil */       #F87171 på rgba(248,113,113,.1)
/* Radius */     8px (knapper/input), 16px (kort)
```

### Tjenestespesifikke unntak

`spekto`/`spekto-dev` har egen palett (grønn tekst `#243d32`, korall knapp `#f47b64`, rust aksent `#a9432c`, radius 10px) via `$isSpekto` i malene. Dette er et unntak, ikke et mønster: neste tjeneste som trenger egen stil skal løses med theming-felter, ikke flere `$isX`-grener.

## Typografi

| Element | Størrelse | Vekt |
|---------|----------|------|
| Tjenestenavn (h1) | 1.5rem lyst / 1.75rem mørkt | 700 / 800, `letter-spacing: -.02em` |
| Tagline | .85rem | 500 lyst / 400 mørkt |
| Knapper | .95rem | 500 (sosiale), 500–600 (primær) |
| Feilmelding | .9rem | 400 |
| Språkvelger | .8rem | 600 for aktivt språk |

## Komponenter (login-sider)

### Kort
```
┌───────────────────────────────┐
│     [logo]  Tjenestenavn      │
│          tagline              │
│                               │
│  [G]  Fortsett med Google     │
│  [■]  Fortsett med Microsoft  │
│  ──────────  eller  ────────  │  (kun mørkt tema)
│  [✉]  Logg inn med e-postlenke│
└───────────────────────────────┘
         nb · en · de
```

- `max-width: 380px`, `padding: 2.5rem 2rem`, sentrert vertikalt og horisontalt, transparent bakgrunn
- Kun de metodene som er aktivert for tjenesten vises — aldri deaktiverte knapper
- Rekkefølge: Google → Microsoft → magic link → (legacy-passord)

### Innloggingsknapper (`.btn-social`)
- Full bredde, `padding: .7rem`, ikon 18×18 + tekst, `gap: .5rem`, `margin-bottom: .5rem`
- Leverandørlogoer i originalfarger — ikke recolor (Google og Microsoft har merkevareretningslinjer)
- Hover: lysere/mørkere flate og kant, `transition: all .15s` i mørkt tema

### Feilmelding (`.msg-error` / `.msg.error`)
- Over knappene, sentrert tekst. Kjente feilkoder (`access_denied`, `invalid_redirect`, `no_account`) oversettes via i18n; ukjente vises rått — unngå å sende interne feilstrenger til malen

### Magic link-side
- Ett e-postfelt med `autofocus`, primærknapp, «Tilbake til innlogging»-lenke
- Innsending via fetch: knapp deaktiveres og viser «Sender …», deretter erstattes skjemaet av bekreftelse («Sjekk innboksen», e-post fremhevet, gyldighetstid)
- **Samme bekreftelse uansett om kontoen finnes** — enumeration-vern er også en UX-regel. Ikke innfør «Fant ingen konto»-tekst etter innsending

### Språkvelger (`.lang`)
- Plassert under kortet: `nb · en · de`, aktivt språk som `<span class="active">`, øvrige som lenker med `hreflang`
- Språket bæres videre i alle lenker (`lang=`-parameter) og settes i `<html lang="{{.Locale}}">`
- Alle brukervendte strenger går via `.T.*` fra `internal/i18n/catalog.go` — aldri hardkodet tekst i login-malene. Nye strenger krever alle tre språk (se `doc/I18N.md`)

## Admin-panelet (`templates/admin/`)

Funksjonelt verktøy for administratorer, ikke merkevareflate. Alltid mørkt, norsk, desktop-først.

```css
/* Bakgrunn */   #0f172a   /* Nav/rad-hover */ #1e293b   /* Kanter */ #334155
/* Tekst */      #e2e8f0  #f1f5f9 (aktiv)  #94a3b8 (labels)  #64748b (hint/th)
/* Primær */     #3b82f6
/* Badges */     grønn #14532d/#86efac · rød #7f1d1d/#fca5a5 · blå #1e3a5f/#93c5fd
/* Radius */     5px (knapper/input), 99px (badges)
```

- **Navigasjon:** Toppstripe «kauth admin» · Brukere · Auditlogg · Tjenester · (spacer) · Logg ut. Aktiv side med `class="active"`
- **Lister:** Full-bredde tabeller (`max-width: 1100px`), `th` dempet, rad-hover, «Rediger» som `btn-outline btn-sm` i siste kolonne
- **Skjemaer:** `max-width: 640px`, seksjoner med `h2`, ett felt per `.form-group` med `label` + input + `.hint`. Avkrysning i `.checkbox-row`
- **Status:** Badges (Aktiv/Inaktiv, Standard, auth-metoder) — ikke fargede tekstceller
- **Hemmeligheter:** client secrets skal være write-only i skjema (tomt felt = uendret)
- **Admin-login** (`admin/login.html`) bruker lyst tema med bakgrunnsbilde, likt sluttbruker-login

## Tilgjengelighet

- `<html lang>` alltid satt til faktisk språk
- Hvert input skal ha en tilknyttet `<label for>` eller `aria-label`. **Kjent gap:** login- og magic-login-malene bruker bare `placeholder`, og flere `<label>` i `admin/service-edit.html` mangler `for` — ikke kopier dette mønsteret, rett det når du er i nærheten
- Synlig fokus: fokusring med `box-shadow` (3px, 15 % alfa av primærfarge) når `outline: none` brukes
- Kontrast: lyst tema over bilder er avhengig av `text-shadow` — sjekk nye bakgrunnsbilder mot WCAG AA for h1, tagline og språkvelger
- Touch-mål: knapper ≥ 44px høye
- `type="email"` + `autocomplete="email"` på e-postfelt
- Feilmeldinger må være tekst, ikke bare farge

## UX-prinsipper

- **Tjenestens ansikt, ikke kauths.** Sluttbrukeren skal kjenne igjen tjenesten (navn, logo, bakgrunn). kauth-merkevare hører hjemme i admin, ikke på login-siden.
- **Ett klikk til leverandøren.** Ingen mellomsteg, ingen kontovalg før Google/Microsoft. Er bare én metode aktiv, er siden fortsatt eksplisitt — ingen auto-redirect uten at tjenesten ber om det.
- **Ingen tekniske detaljer til sluttbruker.** OIDC-feil, state-mismatch og utløpte lenker forklares i klartekst med en vei videre («Prøv igjen»), aldri stacktrace eller protokollkoder.
- **Ikke avslør kontostatus.** Gjelder magic link, feilmeldinger og tidsbruk.
- **Graceful degradation.** Uten JS skal innlogging fortsatt fungere; uten bakgrunnsbilde faller siden tilbake til `bg_css` eller nøytral bakgrunn.

## Ytelse og levering

- Bakgrunnsbilder er den tyngste ressursen (60–530 KB i `static/`). Nye bilder: webp, ≤ 250 KB, ca. 1920px bredde
- Ingen eksterne skript. Eksterne fonter kun som tjenestespesifikt unntak, med `preconnect` og `display=swap`
- `prefers-reduced-motion`: hold animasjoner til fargeoverganger (150 ms); ingen bevegelse som er nødvendig for forståelsen

## Responsivitet

- **Mobil først for login:** kortet er 100 % bredde med `margin: 1rem` opp til 380px
- **Admin er desktop-først:** tabeller kan scrolle horisontalt på mobil — akseptabelt for et adminverktøy, ikke for login
- `meta viewport` på alle sider; ingen horisontal scrolling på login-sidene
