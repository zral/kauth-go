# Architecture Design Notes — kauth-go

Sentral beslutningslogg for arkitektur- og designvalg i kauth-go. Hver ADN er en kort, datert oppføring som forklarer *hvorfor*, ikke bare *hva*.

**Nummerering:** ADN 1–6 og feature 001–006 ble ført i Quarkus-versjonen (`quarkus-simple-auth/doc/ARCHITECTURE_DESIGN_NOTES.md`). Beslutningene der gjelder fortsatt for kauth-go, som er en port av samme tjeneste. Nummereringen fortsetter derfor fra ADN 7 og feature 007.

| ADN | Tema (Quarkus-loggen) |
|---|---|
| 1 | `org`-claim som JSON-array i JWT |
| 2 | Refresh token med rotasjon og family-revokering |
| 3 | Per-tjeneste access-token TTL |
| 4 | Datadrevet refresh-token familygrense |
| 5 | `aud`-claim i JWT + `service_id` på refresh tokens |
| 6 | Per-tjeneste OAuth-klient for branding på consent-skjerm |

> ADN 5 sier at access-tokens skal ha `aud` og at refresh-tokens bindes til `service_id`. Kauth-go setter i dag `aud` bare i code-flyten, og refresh-grant bruker ikke det lagrede `service_id` (ROADMAP H2, H5). Porten har altså gått bort fra ADN 5. Fase 0–1 retter det.

---

## ADN 7 — kauth-go er en identity broker, ikke en autentiseringsplattform (2026-10-13)

**Status:** Besluttet

**Beslutning:** Kauth-go delegerer autentiseringen til etablerte leverandører (Google, Microsoft, magic link til brukerens e-post, senere generisk OIDC). Kauth eier identitet, kontokobling, autorisasjon (roller, org og policy per tjeneste), sesjoner og tokenutstedelse. Prinsippet er «Delegate authentication. Own identity and authorization.»

**Begrunnelse:** Google og Microsoft er bedre på passkeys, MFA, kontogjenoppretting og deteksjon av kontoovertakelse enn et lite prosjekt kan bli. Hver autentiseringsmekanisme kauth bygger selv, er sikkerhetskritisk kode som må eies for alltid. Konkurransefortrinnet mot Authelia, Keycloak og Zitadel er *mindre* sikkerhetskritisk kompleksitet, ikke flere funksjoner.

**Konsekvens:**
- Utenfor scope: egen WebAuthn/passkeys, TOTP/HOTP, passord som fremtidig metode, LDAP, SAML og Postgres/Redis.
- Apple Sign In ligger i backlog på grunn av løpende kostnad (Apple Developer Program). Provider-arkitekturen skal gjøre den til en adapter senere.
- At innloggingen er delegert, betyr ikke at MFA er brukt. Kauth må selv ha en policy for hvor mye det stoler på hver leverandør, og for magic link spesielt.
- Kontokobling blir den mest sikkerhetskritiske delen av kauth (se ROADMAP B1).

**Grunnlag:** Produktstrategi drøftet med ChatGPT og ekstern revisjon, [ROADMAP.md](ROADMAP.md).

---

## ADN 8 — Dark Software Factory-oppsett portert fra vinkjeller (2026-10-13)

**Status:** Besluttet

**Beslutning:** Kauth-go bruker DSF-pipelinen fra vinkjeller: approval gates, faset livssyklus, holdout-scenarier, lifecycle-telemetri og spesialiserte review-agenter. Stack-spesifikke deler er tilpasset Go: test-kommandoer, filsti-triggere og en eval-server som bygger binæren mot en isolert DB med ferske nøkler.

**Begrunnelse:** Kauth er sikkerhetskritisk infrastruktur for flere tjenester. Verifiseringen 2026-10-13 fant feil som ingen dokumentbasert gjennomgang så (ROADMAP K1–K3, H1, H2). Det krever en prosess der negative scenarier skrives før koden og security-review kjøres på alle auth-diffs.

**Konsekvens:** Selve oppsettet holdes lokalt og er ikke en del av det offentlige repoet. Det gjelder hooks, skills, driver- og eval-skript, analyse- og plandokumenter og holdout-scenarier. Bare beslutningsloggen, ROADMAP og BACKLOG er sporet. Holdout-scenariene beskriver dessuten sårbarheter i detalj før de er rettet.

---

## ADN 9 — Tokenformål og tjenestebinding håndheves av kauth, ikke av URL-en eller klienten (2026-10-13)

**Status:** Godkjent (analyse 2026-10-13)
→ Analyse: [doc/features/007_AN_AKUTT_HERDING.md](features/007_AN_AKUTT_HERDING.md)

**Beslutning:**
1. **`Verify` krever forventet formål.** Kallere oppgir hvilken `token_use` de forventer (og `aud` der den finnes). Ingen endepunkter godtar et «gyldig kauth-JWT» generelt. Admin-tokens får `aud=kauth-admin` med én gang. `aud` på access-tokens kommer i Fase 1 (H5, i tråd med ADN 5).
2. **En sesjon opprettes bare der autentiseringen skjedde.** Admin-sesjonen settes i OIDC-callbacken (formålet ligger i den HMAC-signerte staten) eller i magic link-verifiseringen. Den lages aldri ved å veksle et token fra en URL.
3. **Refresh-tokenets lagrede tjeneste er autoritativ.** `service_id` fra klienten er bare et hint. I Fase 0 blir avvik logget og ignorert, i Fase 1 avvist. Policy (`require_role`/`enforce_org`) kjøres ved hver refresh mot den lagrede tjenesten. Rader uten tjeneste avvises.
4. **Redirect-mål er eksakte registrerte URL-er.** Det finnes ingen unntak for interne stier.
5. **Tokens skal aldri i loggen.** Request-loggen hvitelister felt (sti, aldri query), slik at nye parametere ikke kan lekke.
6. **Innstramminger som kan bryte klienter, innføres med logging først** (L4 og H2-avvik i Fase 0) og håndheves når dataene viser at det er trygt.
7. **Nettverksgrensen er loopback.** Kauth lytter på 127.0.0.1, og klient-IP hentes fra `CF-Connecting-IP` bare når forbindelsen kommer fra loopback.

**Begrunnelse:** Verifiseringen 2026-10-13 (ROADMAP K1, K2, H2) viste at tre uavhengige feil hadde samme rot: kauth stolte på det URL-en eller klienten påsto (et vilkårlig JWT i `?token=`, en `service_id` i skjemaet, en intern sti i en usignert cookie) i stedet for på sin egen tilstand. ADN 5 fra Quarkus-versjonen sa allerede at refresh skal bindes til `service_id`. Porten mistet det. Å lukke hver feil for seg, uten et prinsipp, inviterer til neste variant.

**Konsekvens:**
- Aktive admin-sesjoner må logge inn på nytt én gang når `aud=kauth-admin` innføres.
- Ingen nye kolonner. Klientenes tokens er uendret i Fase 0.
- Fase 1 bygger videre med `aud` på alle tokens, avvisning av `service_id`-avvik, eventuelt håndheving av L4, og CSRF-vern som tar høyde for at `Referrer-Policy: no-referrer` gir `Origin: null` på skjema-POST.

**Tillegg (2026-10-13, fra 007 F5):** Kauth sender `Referrer-Policy: no-referrer`. Derfor sender nettleseren `Origin: null` på kauths egne skjema-POST-er. CSRF-vern for admin og andre skjemaer (Fase 1) skal bruke `Sec-Fetch-Site: same-origin` eller et CSRF-token, ikke Origin. `Origin: null` skal aldri godtas. Origin-sjekken på `/token` (007 F7) påvirkes ikke, fordi den kalles fra appenes egne sider.

---

## ADN 10 — Føderert identitet krever leverandørbekreftet e-post, og refresh-familier revokeres som helhet (2026-10-13)

**Status:** Vedtatt (2026-10-13)
→ Analyse: [doc/features/008_AN_HERD_FLYTER.md](features/008_AN_HERD_FLYTER.md)

**Beslutning:**
1. **E-post fra en leverandør brukes bare når leverandøren har bekreftet den.** Google: `email_verified == true`, i alle grener. Microsoft: en personlig konto gjenkjennes bare på `tid == 9188040d-6c67-4c5b-b112-36a304b66dad`. En organisasjonskonto krever `xms_edov == true`. Et manglende claim tolkes aldri som «personlig konto». Det er ingen fallback til `preferred_username`. `iss` valideres mot `tid`.
2. **Den signerte OIDC-staten bærer nonce og utstedelsestid.** Nonce sendes til leverandøren og sjekkes mot `id_token.nonce`. En state eldre enn 10 minutter avvises. Det blir ingen ny tilstand på serveren.
3. **Feil i føderert innlogging gir en generisk feilkode på innloggingssiden, aldri feiltekst fra biblioteket og aldri en automatisk ny runde mot leverandøren.** Årsaken går til audit og logg.
4. **En refresh-familie er enheten for tilbaketrekking.** Rotasjonen (konsum + barn) er én transaksjon. Gjenbruk eller presentasjon av et revokert token revokerer hele familien uansett `used`. Logout revokerer familien til cookien, og deaktivering revokerer alle familiene til brukeren.
5. **Ingen toleransevindu for samtidig refresh.** Prod-data (17 reuse, 11 av dem samtidige kall fra klarsyn før klientens single-flight-fiks 2026-07-28, 0 reuse på 1 406 rotasjoner siden 2026-08-18) viser at problemet er løst hos klienten. Reuse-audit får tidsgap, slik at et vindu kan innføres på data hvis behovet kommer tilbake.
6. **Avvisning av `service_id`-avvik ved refresh (ADN 9 pkt 3) utsettes.** Den lagrede tjenesten er allerede autoritativ, så avvisning tetter ingen hull. Datagrunnlaget (4 rotasjoner) er for tynt til å utelukke legitime klienter.

**Begrunnelse:** ADN 7 sier at kauth eier identiteten. Da må kauth også eie beslutningen om *hvilke* påstander fra en leverandør som er gode nok til å bli identitet. Uten den kan e-post fra en fremmed Entra-tenant ta over en eksisterende konto (nOAuth, ROADMAP H4). For refresh sier OAuth Security BCP (RFC 9700 §4.14.2) at gjenbruk skal ugyldiggjøre den aktive tokenen. Det holder bare hvis rotasjonen er atomisk og revokeringen treffer hele familien (ROADMAP H6). At logout ikke revokerte noe, var et tap fra Quarkus-porten: de 115 `user_logout`-revokeringene i prod er alle fra mai 2026, før kauth-go fantes.

**Konsekvens:**
- `xms_edov` må konfigureres som optional claim i begge Entra-appene (`bcc08970-…` «Klarsyn» og `6e5fb3bf-…` for spekto/spekto-dev) før håndhevingen deployes. Ellers avvises organisasjonskontoer (0 i prod i dag).
- Ingen migrasjon og ingen endring i tokens eller claims. Innlogginger som pågår rundt deploy, feiler én gang.
- Et ekte refresh-race logger nå ut begge parter i stedet for tilfeldig den ene.
- Varig identitet på `(tid, oid)` og `tid`-allowlist per tjeneste kommer i Fase 2/5 (ROADMAP B1, B5).

---

## ADN 11 — Engangshemmeligheter lagres som hash og brukes opp bare ved en bevisst handling fra samme origin. Admin-tilgang og audit følger DB-en (2026-10-13)

**Status:** Implementert (2026-10-14). Vedtatt 2026-10-14, i prod som `009-a` og `009-b`
→ Analyse: [doc/features/009_AN_HERD_FLYTER_DEL2.md](features/009_AN_HERD_FLYTER_DEL2.md)

**Beslutning:**
1. **Alle engangshemmeligheter lagres bare som SHA-256-hash**, slik refresh-tokens allerede gjør. Det gjelder magic-tokens (tjeneste og admin) og autorisasjonskoder. Hashingen skjer i én funksjon i `internal/token`. Skjemaendringer er additive (`ADD COLUMN`, tømming), slik at rollback fortsatt er forrige binær.
2. **En GET bruker aldri opp en hemmelighet.** En magic link viser en bekreftelsesside med én knapp. Konsumet skjer på POST. Det gjelder også `/admin/verify`. Siden har tjenestens tema og viser ikke e-postadressen.
3. **Tilstandsendrende POST fra nettleseren krever samme origin:** `Sec-Fetch-Site: same-origin`, eller, når headeren mangler, en `Origin` lik egen origin. `same-site` er ikke nok, fordi søster-apper under samme domene er trusselen. `Origin: null` godtas aldri (ADN 9-tillegget). Sjekken er middleware for hele `/admin` og brukes også på bekreftelses-POST for magic link.
4. **`/logout` forblir GET**, men revokerer og sletter cookies bare ved bevisst navigasjon: samme origin eller same-site, toppnivå-navigasjon (`Mode=navigate`, `Dest=document`), eller ingen `Sec-Fetch-*`. Cross-site-underressurser og iframes endrer ingenting.
5. **Tjenesten til et magic-token er den lagrede.** URL-en er bare et tema-hint. Formålet (`service`/`admin`) er en egen kolonne som håndheves i `WHERE`. Rate limit er en betinget innsetting i DB per normalisert e-post og formål, så innsetting, limit og «ingen e-post ved feil» er én operasjon.
6. **En autorisasjonskode brennes bare når klient, `redirect_uri` og PKCE stemmer.** Konsum og første refresh-rad er én transaksjon, og koden husker familien sin. Gjenbruk revokerer den familien (RFC 6749 §4.1.2).
7. **Admin-tilgang slås opp i DB ved hver forespørsel.** Det signerte admin-tokenet er nødvendig, men ikke tilstrekkelig. Deaktivering eller fjernet `konge` virker umiddelbart.
8. **Audit skrives via en begrenset kø med én skriver, og køen tømmes ved shutdown.** Ved full kø droppes hendelser med tellende logg. Admin-skriv auditeres synkront med aktør. `/token` og innlogging blokkeres aldri av audit.
9. **E-post normaliseres (`trim` + `lower`) ved inngang**, og databasen har en unik indeks på normalisert e-post, slik at duplikater ikke kan oppstå stille.

**Begrunnelse:** ADN 9 sa at kauth skal stole på sin egen tilstand, ikke på URL-en. 009 utvider prinsippet til nettleseren og til lagring: en lenke som åpnes av en e-postskanner, en POST fra en søster-app og et 8-timers JWT for en admin som er fjernet, er alle tilfeller der kauth handler på noe den ikke har sjekket. Klartekst-hemmeligheter i DB gjør en lesbar backup til en innlogging. Fetch Metadata gir CSRF-vern uten ny tilstand og uten endring i skjemaene, og `Referrer-Policy: no-referrer` (007 F5) gjør `Origin` alene ubrukelig. Prod-data (0 rader i begge engangstabellene, 0 e-poster som ikke er normalisert, maks 4 audit-hendelser/s) gjør endringene trygge å innføre nå.

**Konsekvens:**
- Magic link krever ett ekstra klikk. Lenker i omløp ved deploy (≤ 15 min) blir ugyldige.
- Nettlesere som verken sender `Sec-Fetch-Site` eller `Origin` kan ikke bekrefte magic link eller bruke admin (fail-closed, under produktbeslutning PB2 i analysen).
- To additive migrasjoner (`purpose` og `family_id`, og unik indeks på `lower(trim(email))`). Tokens og claims er uendret.
- Access-tokens fra en gjenbrukt kode lever ut TTL til `jti` finnes (H5, 010).
- Limit per IP på bestilling av magic link står igjen (BACKLOG).
- Akseptert restrisiko, login-CSRF (P1): bekreftelsessiden viser ikke e-postadressen. Et offer som trykker på en lenke en angriper har bestilt til sin egen adresse, kan dermed logges inn som angriperen (sosial manipulering).
- Akseptert restrisiko, logout (P2/PB3): `same-site` og bar GET revokerer. En kompromittert søster-app, eller toppnivå-navigasjon fra en annen side, kan logge brukeren ut. Det gir en uønsket utlogging, ingen tilgang.
- Akseptert restrisiko: 3 bestillinger per 15 min blokkerer offerets magic link (kvote-DoS, som før).

---

## ADN 12 — Access-tokens bærer `aud` = tjeneste-ID og `jti`. Klientene håndhever `aud` i egne leveranser (2026-10-14)

**Status:** Implementert (2026-10-14). I prod som tag `010`
→ Analyse: [doc/features/010_AN_HERD_FLYTER_DEL3.md](features/010_AN_HERD_FLYTER_DEL3.md)

**Beslutning:**
1. **Alle access-tokens har `aud = [svc.ID]`** for tjenesten de ble utstedt for, uansett innloggingsmetode og også etter refresh. Et refreshet token arver refresh-familiens lagrede tjeneste, aldri tjenesten fra requesten. Dette gjeninnfører Quarkus-ADN 5. id_token (`aud=[svc.ID]`, `token_use=id`) og admin-token (`aud=["kauth-admin"]`, `token_use=admin`) er uendret.
2. **Alle signerte tokens har en `jti`** (128 bit, ikke lagret). Den brukes til korrelasjon i audit og som grunnlag for en senere denylist eller introspection.
3. **Kauth håndhever `aud` der kauth selv veksler tokenet til noe nytt:** `/dispatch` nivå 0 lager bare en kode for klienten som står i `aud`, og bare for et ferskt token (PB1). Nivå 1–5 auditeres foreløpig, uten avvisning.
4. **Tilbaketrekking av access-tokens er ikke mulig hos klientene**, fordi de validerer lokalt. Kort TTL er tiltaket. Ved gjenbruk av en kode logger kauth `jti` og familie, men lover ikke mer.
5. **Kontrakt for klientene:** `aud` kan komme som streng eller som array. Klienten godtar sin egen tjeneste-ID (tabell i analysen §3 A6) og krever `token_use == "access"`. Access- og id_token har samme `aud`, så klientene må også sjekke `token_use` for id_token og `nonce`. `typ: at+jwt` vurderes senere. Hver klient innfører sjekken i en egen leveranse, tidligst én access-TTL og én refresh-syklus etter at kauth med `aud` er i prod.
6. **Tjenestevalg følger én regel for alle innloggingsmetoder.** En eksplisitt tjeneste-ID vinner over hosten bare når tjenesten ikke har egen `auth_host`, eller når den har akkurat denne hosten (PR #6, nå også for magic link og passord). En tjeneste uten egen `auth_host` kan bindes fra enhver host. Det er bevisst, fordi undertjenester deler host med foreldretjenesten. Policy, `aud` og callback følger den bundne tjenesten.

**Begrunnelse:** Uten `aud` er et token for én tjeneste gyldig hos alle de andre, og `/dispatch` kan gjøre et token for B om til en kode for A. Kauth kan ikke tvinge klientene til å sjekke, men kan sørge for at informasjonen finnes og håndheve den selv. Å legge til `aud` brekker ingen klient (kartlagt 2026-10-14). Å kreve den er en separat endring per klient med egen risiko.

**Konsekvens:**
- Ingen klient er beskyttet mot tokens på tvers av tjenester før den selv sjekker `aud`.
- analyse.klarsyn.net er samme app som klarsyn (klarsyn-web). Den logger inn som `klarsyn` og får `aud=klarsyn`. Tjenesteraden `analyse` er i praksis ubrukt.
- Univers (TTL 12 t) er den største eksponeringen for lekkede access-tokens, uavhengig av `aud`.

---

## ADN 13 — Identitet er en kobling `(issuer, subject)` til en intern bruker med opak `public_id`. E-post er et attributt (2026-10-14)

**Status:** Implementert (2026-10-15). I prod som tag `011`
→ Analyse: [doc/features/011_AN_STABIL_IDENTITET.md](features/011_AN_STABIL_IDENTITET.md) · Plan: [doc/features/011_PL_STABIL_IDENTITET.md](features/011_PL_STABIL_IDENTITET.md)

**Beslutning:**
1. **En ekstern identitet er `(issuer, subject)`** i `user_identities`, unik og knyttet til én bruker. Google: kanonisk issuer `https://accounts.google.com` (uansett om `iss` kommer med eller uten `https://`) og `sub`. Microsoft: `https://login.microsoftonline.com/{tid}/v2.0` med `tid` i små bokstaver, og `oid` i små bokstaver. `oid` er påkrevd og må være en GUID, ellers avvises innloggingen (`reason=missing_oid`). Grunnen er at `sub` er parvis per Entra-app og kauth har to apper.
2. **Innlogging slår opp identiteten først.** En koblet identitet vinner over e-posten i claimet. En ukjent identitet kobles til brukeren med samme leverandørbekreftede e-post (ADN 10), eller registreres. Om koblingen skjer, styres av `auto_link` per tjeneste (default 1, som i dag). Med `auto_link=0` kobles bare brukerens første fødererte identitet på e-post (overgangsunntaket). Koblingen er en atomisk betinget `INSERT`, slik at to samtidige innlogginger ikke begge slipper gjennom. Deretter avvises nye kontoer med `account_not_linked` til eksplisitt kobling finnes (012). Koblingene er globale for brukeren, og policyen til tjenesten der innloggingen skjer, gjelder.
3. **Admin-Google godtar bare én admin-godkjent identitet** (`user_identities.admin_ok`, PD8b). Admin-Google registrerer aldri brukere og kobler bare brukerens første identitet (overgangsunntaket, som `auto_link=0`). Første admin-Google-innlogging etter deploy, etter `konge`-sjekken, godkjenner identiteten med en betinget `UPDATE` (bare når brukeren ikke har noen godkjent identitet). Deretter avvises alle andre kontoer mot admin, også de som er koblet via en tjeneste med `auto_link=1`. Admin via magic link er uendret.
4. **Magic link lagres ikke som identitet.** Magic-identiteten *er* `users.email`, og kan aldri være sterkere enn e-postkontoen bak.
5. **Hver bruker har en `public_id`** (UUID v4 fra `crypto/rand`) som aldri endres. Den er `sub` for tjenester med `sub_format=id`. Default `email` gir uendrede tokens (golden-test). Klientene bytter én og én i egne leveranser, og matcher eksisterende brukere på `email`-claimet første gang. `/dispatch` nivå 0 krever at `sub` tilhører brukeren: for `id`-tjenester slås brukeren opp på `public_id` og e-postclaimet må stemme, for `email`-tjenester på normalisert e-post. Avvik gir `dispatch_subject_mismatch`.
6. **Refresh-familier og autorisasjonskoder bindes til `user_id`.** Rotasjon arver den. En rad uten `user_id` behandles som inaktiv bruker (refresh-familien revokeres med `user_inactive`, koden gir `invalid_grant`), uten e-post-fallback, fordi en fallback ville bundet en gammel familie til en konto som senere opprettes med samme adresse. E-post blir værende på radene for audit.
7. **E-postoppslag er eksakt mot Go-normalisert verdi** (`email = ?`). Det løser Unicode-bretting (`Ø` mot `ø`). Migrasjonen har en vakt som stopper ved ikke-normaliserte eller ikke-ASCII e-poster i stedet for å slå sammen brukere, og ruller tilbake hele migrasjonen.
8. **`users.email` endres ikke automatisk** når leverandørens e-post endres (avvik gir audit `identity_email_mismatch`). E-postendring, eksplisitt kobling, frakobling og recovery kommer i 012.

**Begrunnelse:** ADN 7 sier at kauth eier identiteten, men i dag er e-postadressen identiteten. Det bryter med OIDC Core §5.7, gjør at en gjenbrukt adresse arver en konto, og gir klientene ingen stabil nøkkel. Fase 3–5 og streng kontokobling (B1) forutsetter en tabell over koblinger.

**Konsekvens:**
- Med `auto_link=1` kan den som kontrollerer en adresse koble en ny leverandørkonto til en eksisterende bruker, med samme tillit som magic link. `auto_link=0` på én tjeneste beskytter ikke mot koblinger som er gjort via en annen tjeneste. Full beskyttelse krever `auto_link=0` på alle tjenestene brukeren bruker. Admin er beskyttet separat av `admin_ok`.
- En bruker med `auto_link=0` som bytter leverandørkonto, kommer ikke inn med den nye kontoen før eksplisitt kobling finnes (012).
- Akseptert: `account_not_linked` røper at kontoen finnes og er koblet, for den som har en verifisert leverandørkonto med den adressen.
- Akseptert: identiteten kobles før `checkPolicy`. Det er konsekvent med at koblinger er globale. En bruker som tjenesten avviser, beholder koblingen.
- Restvindu for admin: fram til hver `konge`-bruker har logget inn i admin med Google én gang etter deploy, kan en kobling gjort via en tjeneste med `auto_link=1` godkjennes som første admin-identitet. Prod har 4 aktive `konge`-brukere. Lars logger inn rett etter restart. Resten godkjennes eller mister `konge` (BACKLOG).
- Ingen identiteter kan fylles inn ved migrering, siden kauth aldri har lagret `sub`/`oid`. De oppstår ved første innlogging etter deploy.
- Rollback til tag `010` er mulig uten `Down`, siden alle nye kolonner har default eller er nullable (verifiseres i røyktesten). Den gamle binæren lager refresh-rader og koder uten `user_id`. Disse avvises ved ny deploy av 011, med mindre backfill-`UPDATE`-ene fra migrasjonen kjøres på nytt først.
- `user_id` har ingen `ON DELETE`, og det finnes ingen trigger mot `UPDATE` av `public_id`. Begge avgjøres når GDPR-sletting kommer (BACKLOG).

---

## ADN 14 — Admin kan koble fra identiteter og endre e-post. Admin-bindingen nullstilles aldri av appen, og tokens som bærer e-post, godtas bare etter brukerens e-postepoke (2026-10-15)

**Status:** Implementert, i prod 2026-10-15 (tag `012`)
→ Analyse: [doc/features/012_AN_ADMIN_IDENTITET.md](features/012_AN_ADMIN_IDENTITET.md)

**Beslutning:**
1. **Frakobling er sletting** av én rad i `user_identities`, betinget på både identitets-ID og bruker-ID. Det er et ryddeverktøy og ingen blokkering: med `auto_link=1` kobles kontoen igjen ved neste innlogging hvis e-posten stemmer. En kompromittert konto håndteres ved å deaktivere brukeren. Frakobling revokerer alle refresh-familiene til brukeren i samme transaksjon. Når alle identitetene er koblet fra, gjelder overgangsunntaket for `auto_link=0` igjen. Det er bevisst.
2. **Admin-bindingen lukkes én gang for alle.** `users.admin_bound_at` settes ved første admin-godkjenning, med en betinget `UPDATE … WHERE admin_bound_at IS NULL`, og `admin_ok` settes bare når den traff. Appen nullstiller aldri feltet, heller ikke ved frakobling. En ny admin-identitet etter tap av den gamle krever en driftsprosedyre (`sqlite3`, logget). Erstatter `NOT EXISTS`-regelen fra ADN 13 pkt 3, som ville åpnet vinduet igjen da den godkjente raden forsvant.
3. **Admin endrer e-post og går god for adressen.** Det sendes ingen bekreftelseslenke. Endringen, `email_changed_at`, revokering av alle familiene til brukeren og brenning av ubrukte magic-tokens for gammel og ny adresse skjer i én transaksjon. Unikheten håndheves av indeksen i selve `UPDATE`-en. Identitetene (`issuer`, `subject`) og `user_identities.email` (sist sett hos leverandøren) røres ikke. Magic link følger `users.email` (ADN 13 pkt 4).
4. **E-postepoke.** Et signert token som identifiserer brukeren med e-post (access-token på `/dispatch` nivå 0, og admin-tokenet), godtas bare når `iat ≥ coalesce(email_changed_at, created_at)` for brukeren oppslaget fant. Et token den gamle eieren av en adresse fikk, virker dermed ikke hos den nye eieren. Ingen fallback. Tokenformatet er uendret.
5. **`RevokeUserRefreshTokens` revokerer bare på `user_id`.** E-postgrenen ville truffet familiene til en tidligere eier av adressen etter en e-postendring. Rader uten `user_id` er døde fra før (ADN 13 pkt 6). Prod har 0 slike.
6. **Recovery er en dokumentert prosedyre** i `doc/FEATURES.md`, uten egen mekanisme. Selvbetjening og eksplisitt kobling venter til en tjeneste trenger `auto_link=0` (Fase 5).

**Begrunnelse:** 011 gjorde e-post til et attributt, men ga ingen måte å endre det på, og ingen måte å fjerne en kobling på, uten å gå i DB-en. Begge er nødvendige når en ansatt slutter og adressen gis videre. Lærdommen fra 011 er at globale koblinger må tenkes gjennom mot admin fra start. Derfor bindes admin-tilgangen til en tilstand på brukeren som bare kan lukkes, og ikke til om en bestemt rad finnes. E-postepoken lukker 011 F2 security M1 med én regel for begge stedene der kauth stoler på en e-post i et signert token, uten å endre claims for klientene (011 P3).

**Konsekvens:**
- E-postendring er en kontraktsendring per bruker for alle `email`-tjenester (i dag alle 7). Klienten ser en ny `sub`. Admin-skjemaet advarer, og endringen skal avtales med tjenesteeieren. Varig løsning er `sub_format=id` per klient (ADN 13).
- Access-tokens med gammel `sub` lever ut TTL hos klientene (ADN 12 pkt 4).
- Akseptert: en `konge` kan ta over en annen konto ved å endre e-posten til en adresse hen kontrollerer. Det følger av at admin går god for adressen. Audit med `actor=`, gammel og ny adresse. Varsel til den gamle adressen er utsatt (BACKLOG).
- En `konge` som endrer sin egen e-post, logges ut av admin. En `konge` som mister sin godkjente Google-konto, beholder admin via magic link.
- 012 endrer ikke admin-vinduet for `konge`-brukere uten godkjent identitet (3 i prod). De bindes ved første admin-Google-innlogging som før.
- Én additiv migrasjon (goose 11, to nullable kolonner). Rollback til tag `011` går, men da gjelder `NOT EXISTS`-regelen igjen.
- Restvindu på ett sekund i epokesammenligningen (`≥` på sekundnivå). Auto-registrering og første token skjer i samme sekund, så `>` ville avvist nye brukere. For å utnytte vinduet trengs et token til den gamle eieren utstedt i samme sekund som adressen byttet eier. Akseptert.
- Klokkehopp bakover kan gi en epoke i fremtiden. Brukeren avvises da til klokka har tatt igjen epoken. Preflight feiler hvis noen epoke ligger i fremtiden.
- Utlogging ved frakobling betyr revokerte refresh-familier. Ved e-postendring brennes også ubrukte magic-tokens. Autorisasjonskoder (TTL 60 s) brennes ikke i noen av tilfellene. En kode utstedt rett før kan løses inn i inntil 60 s og gir en ny sesjon med vanlig levetid, men alltid for samme bruker (koden er bundet til `user_id`). Akseptert. Deaktivering stopper også kodene.
- Rollback: rull tilbake binæren. Kjør aldri `goose down` for migrasjon 011 etter at frakobling er brukt, fordi en ny `Up` bare binder brukere som fortsatt har en `admin_ok`-identitet. Ved ny deploy etter en rollback kjøres backfill-`UPDATE`-en fra migrasjonen på nytt, ellers står en `konge` som ble godkjent under rollbacken, ubundet.

**Presiseringer fra implementeringen:**
- **Epokeformater.** `token.ParseEpoch` tolker `2006-01-02T15:04:05Z` (det kauth skriver) og SQLite `datetime()` (`2006-01-02 15:04:05`, UTC), slik at seed-SQL i tester og eval ikke låser ute. Alt annet er utolkbart og gir avvisning (fail-closed). Manglende `iat` avvises også. Sammenligningen er `iat.Unix() >= epoke.Unix()`. Preflight bruker samme funksjon.
- **Begge `sub_format`-grener.** `/dispatch` nivå 0 sjekker epoken etter oppslaget og `sub`-sjekken, for både `email` og `id`. For `id`-tjenester er den overflødig, siden et token med gammel e-post allerede er avvist av e-postlikheten. Én sjekk for begge er enklere å resonnere om. Avvisning gir `dispatch_subject_mismatch` med `level=0 reason=email_reassigned`. Admin-middlewaren avviser med 303 til `/admin/login` (401 for JSON) og logger bruker-ID-en.
- **Binding i én transaksjon.** `BindAdmin` (betinget på `admin_bound_at IS NULL`) og deretter `SetAdminOK` kjører i samme transaksjon. `SetAdminOK` er betinget på at `admin_bound_at` er verdien denne transaksjonen skrev (`EXISTS … admin_bound_at = bound_at`). Treffer `BindAdmin` ingen rad, er brukeren bundet fra før, og innloggingen avvises med `reason=not_admin_identity`. Treffer `SetAdminOK` ingen rad, rulles bindingen tilbake og innloggingen avvises med `reason=identity_vanished`. Audit `identity_admin_approved` får `bound=1`.
- **Audit-grunner.** `identity_unlinked` (med `provider`, `issuer`, `admin_ok`, `revoked`), `user_email_changed` (med `old=`, `revoked`, `burned`) og `identity_link_denied reason=identity_vanished`. Begge admin-skrivene får `actor=`. Subject logges ikke.
- **Transaksjonene starter med en skriving** (`DeleteIdentity` ved frakobling, `RevokeUserRefreshTokens` ved e-postendring), slik at skrivelåsen tas før første lesing. Ellers kan en samtidig skriver gi `SQLITE_BUSY_SNAPSHOT`, og e-postendringen ville svart 500 i stedet for 409.

## ADN 15 — E-postepoke på `/dispatch` nivå 1–5, med fail-open ved DB-feil og ferskhet som audit (2026-10-16)

**Status:** Implementert (2026-10-16, 013)
→ Analyse: [doc/features/013_AN_DISPATCH_EPOKE.md](features/013_AN_DISPATCH_EPOKE.md)

**Beslutning:**
1. Før nivå 1–5 ruter, slår `/dispatch` opp den aktive brukeren med e-posten i tokenet. Tokenet sendes bare videre når brukeren finnes, `sub` er brukerens e-post eller `public_id`, og `iat` finnes og ikke er eldre enn brukerens e-postepoke (ADN 14 pkt 4). Ellers går brukeren til `/login` og det logges `dispatch_subject_mismatch` med `level=1-5 reason=…`.
2. `sub` godtas i begge former, fordi målet på nivå 1–5 ikke alltid er tokenets `aud`, og tjenestens `sub_format` dermed ikke kan avgjøre tolkningen.
3. En DB-feil i oppslaget stopper ikke innloggingen (fail-open, logget med `slog.Error`). Konstatert avvik avvises.
4. Et token på nivå 1–5 som er eldre enn 120 s (eller mer enn 30 s fram i tid), logges som `dispatch_token_stale … mode=audit` og videresendes. Håndheving avgjøres senere på grunnlag av auditen.

**Begrunnelse:** Én regel for alle stedene kauth håndterer et access-token som bærer e-post. Eval 012 (T4.2, T4.3, T4.5) viste at nivå 1–5 videresendte tokens utstedt før en e-postendring.

**Konsekvens:**
- Sjekken er et konsistenslag. Den trekker ikke tilbake tokens. Den som har et gammelt token, kan fortsatt gå rett til tjenestens callback, og klientenes egen validering gjelder (ADN 12). Login-CSRF via `?token=` løses først av en engangs-handoff (BACKLOG).
- Ett indeksert DB-oppslag per `/dispatch`-kall på nivå 1–5.
- Et levende token for en deaktivert bruker sendes heller ikke videre på nivå 1–5.

**Presiseringer fra implementeringen:**
- **Manglende `iat`** avvises med egen grunn `iat_missing`, som ADN 14 krever. kauth utsteder alltid `iat`, så grunnen skiller et slikt token fra en omtildelt adresse.
- **Fail-open er synlig.** DB-feil gir `slog.Error` og audit `dispatch_subject_check_skipped` (`level=1-5 reason=db_error`, success=1). `context.Canceled` (klienten koblet fra) logges ikke. En epoke som ikke kan tolkes, er fortsatt fail-closed (`email_reassigned`), som på nivå 0.
- **Ferskhets-auditen** skrives før rutingen. Har nivå 5 ingen default-tjeneste, ender kallet på `/login`, men raden har success=1. Det kan bare skje ved feilkonfigurasjon. Akseptert.
