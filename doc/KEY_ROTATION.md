# Nøkkelrotasjon og klienthemmeligheter

Driftsprosedyre for 017 (ADN 19). Gjelder JWT-signeringsnøkkelen og Google/Microsoft-hemmelighetene per tjeneste. Alt styres av `.env` og restart; ingenting ligger i admin-UI.

Variablene under står i `.env.example`. Antakelser: `.env` ligger i `/home/lars/kauth-go`, tjenesten heter `kauth` i systemd. Sett databasestien (den er relativ i `.env`):

```bash
cd /home/lars/kauth-go && KAUTH_DB_PATH=$(grep '^KAUTH_DB_PATH=' .env | cut -d= -f2-)
```

## 1. Nøkkelringen

| Rolle | Variabler | Signerer | Publisert i JWKS | Godtas i `Verify` |
|---|---|---|---|---|
| current | `KAUTH_PRIVATE_KEY_*`, `KAUTH_PUBLIC_KEY_*`, `KAUTH_SIGNING_KID` (default `kauth-1`) | ja | ja, først | ja |
| next | `KAUTH_NEXT_PUBLIC_KEY_PATH` (eller `_PEM`), `KAUTH_NEXT_KID` | nei | ja | nei |
| previous | `KAUTH_PREVIOUS_PUBLIC_KEY_PATH` (eller `_PEM`), `KAUTH_PREVIOUS_KID` | nei | ja | ja |

Nøkkel og `kid` hører sammen: setter du det ene må du sette det andre. `kid` er `A-Z a-z 0-9 . _ -`, maks 64 tegn, og unik i ringen. RSA minst 2048 bit. Gal konfig stopper oppstarten med en melding som navngir variabelen. Bruk enten `_PEM` eller `_PATH` for samme nøkkel, aldri begge.

## 2. Hvorfor ventetidene

- Klientene cacher JWKS. pov (spekto) cacher i 1 time, velger nøkkel etter `kid`, bruker `keys[0]` når tokenet mangler `kid`, og **henter ikke JWKS på nytt ved ukjent `kid`**. En ny nøkkel må derfor ha vært publisert lenger enn cachen før den begynner å signere, ellers feiler verifiseringen til cachen går ut.
- Current står alltid først i JWKS, fordi `keys[0]` er fallback.
- Tokens signert med den gamle nøkkelen lever til de utløper. Lengste TTL er den største av `KAUTH_ADMIN_TOKEN_TTL` og `access_token_ttl` i `services` (sjekk med `sqlite3 "$KAUTH_DB_PATH" "SELECT id, access_token_ttl FROM services;"`). Previous må bli stående til alle slike tokens er utløpt.

## 3. Planlagt rotasjon

Ta backup av `.env` først: `cp -p .env .env.bak-$(date +%F)`.

**Steg 1: publiser ny nøkkel (next).**

```bash
umask 077
mkdir -p secrets
openssl genpkey -algorithm RSA -out secrets/privateKey-2.pem -pkeyopt rsa_keygen_bits:3072
openssl rsa -in secrets/privateKey-2.pem -pubout -out secrets/publicKey-2.pem
```

I `.env`:

```
KAUTH_NEXT_PUBLIC_KEY_PATH=./secrets/publicKey-2.pem
KAUTH_NEXT_KID=kauth-2
```

`sudo systemctl restart kauth`. Sjekk at JWKS har to nøkler, `kauth-1` først (se §4).

**Steg 2: vent.** Minst 1 time (pov-cachen) pluss margin. I praksis til neste dag.

**Steg 3: bytt.** I `.env`: current blir det nye paret, den gamle offentlige nøkkelen blir previous, next fjernes.

```
KAUTH_PRIVATE_KEY_PATH=./secrets/privateKey-2.pem
KAUTH_PUBLIC_KEY_PATH=./secrets/publicKey-2.pem
KAUTH_SIGNING_KID=kauth-2
KAUTH_PREVIOUS_PUBLIC_KEY_PATH=./secrets/publicKey.pem
KAUTH_PREVIOUS_KID=kauth-1
# KAUTH_NEXT_* fjernes
```

Tokens uten `kid` (utstedt før 017) godtas bare av kauth selv: pov bruker `keys[0]`, som etter byttet er den nye nøkkelen. Første rotasjon må derfor skje tidligst lengste TTL etter at 017 er deployet.

Restart. Nye tokens har `kid: kauth-2`; gamle tokens (med eller uten `kid`) godtas fortsatt via previous. JWKS: `kauth-2`, `kauth-1`.

**Steg 4: fjern previous.** Etter lengste token-TTL (se §2) pluss JWKS-cache (1 t), i praksis neste dag: fjern `KAUTH_PREVIOUS_*` fra `.env` og restart. Slett den gamle private nøkkelen når du er sikker på at du ikke skal rulle tilbake.

## 4. Sjekke

```bash
curl -s https://<issuer>/.well-known/jwks.json | python3 -c 'import json,sys;print([k["kid"] for k in json.load(sys.stdin)["keys"]])'
```

`kid` i et token (header er første segment):

```bash
echo "$TOKEN" | cut -d. -f1 | tr '_-' '/+' | base64 -d 2>/dev/null; echo
```

Forventet `{"alg":"RS256","kid":"kauth-2","typ":"JWT"}`. Sjekk også at innlogging og `/api/me` virker, og at oppstartsloggen ikke har feil.

## 5. Rollback

Før steg 3 er current uendret: fjern `KAUTH_NEXT_*` og restart. Etter steg 3, mens previous fortsatt står: sett tilbake gammel `KAUTH_PRIVATE_KEY_PATH`, `KAUTH_PUBLIC_KEY_PATH` og `KAUTH_SIGNING_KID=kauth-1`, og sett `KAUTH_PREVIOUS_PUBLIC_KEY_PATH=./secrets/publicKey-2.pem` med `KAUTH_PREVIOUS_KID=kauth-2` (tokens signert med den nye godtas bare som previous). Fjern `KAUTH_NEXT_*`, og bruk aldri samme kid to ganger i ringen, ellers stopper oppstarten på duplikat-kid. Restart. Gjenopprett `.env` fra backupen om noe er uklart. Ingen tokens blir ugyldige så lenge nøkkelen som signerte dem står som current eller previous.

## 6. Nødrotasjon (kompromittert nøkkel)

Her skal den gamle nøkkelen **ikke** godtas lenger. Previous godtas av `Verify`, så en kompromittert nøkkel satt som previous lar angriperen forfalske tokens til TTL går ut. Derfor:

1. Stopp tjenesten først, så den gamle prosessen ikke kan rotere refresh-tokens etter revokeringen: `sudo systemctl stop kauth`.
2. Ta backup: `sqlite3 "$KAUTH_DB_PATH" ".backup /home/lars/kauth-pre-revoke.db"`.
3. Revoker alle refresh-familier, ellers kan en angriper med et tidligere utstedt refresh-token få nye gyldige tokens. Det finnes ingen revoker-alle i admin (`RevokeUserRefreshTokens` gjelder én bruker), så bruk SQL:

```bash
sqlite3 "$KAUTH_DB_PATH" "UPDATE refresh_tokens SET revoked = 1, revoked_reason = 'key_compromise' WHERE revoked = 0;"
```

4. Lag nytt par (som i steg 1) og endre `.env`: nytt par som current med ny `KAUTH_SIGNING_KID`, **ingen** `KAUTH_PREVIOUS_*`, ingen `KAUTH_NEXT_*`.
5. Start: `sudo systemctl start kauth`. Alle eksisterende access- og admin-tokens er ugyldige, og alle brukere må logge inn på nytt. Klienter som har den gamle nøkkelen cachet i opptil 1 time, og ikke henter på nytt ved ukjent `kid`, avviser de nye tokensene til cachen går ut. Si fra til tjenesteeierne, eller be dem restarte.
6. Sjekk JWKS: bare den nye nøkkelen. Fjern den kompromitterte privatnøkkelen fra alle steder den ligger, inkludert backuper du kontrollerer.

## 7. Klienthemmeligheter

Google- og Microsoft-hemmelighetene per tjeneste ligger som navn på en miljøvariabel i `services.google_client_secret_env` og `services.microsoft_client_secret_env`. Verdien står i `.env`. Navnet **må** begynne med `KAUTH_SVC_` og bare bestå av `A-Z 0-9 _` (maks 64 tegn); det håndheves både i databasen og i koden, og i admin (422 ved feil). Konvensjon: `KAUTH_SVC_<ID>_GOOGLE_SECRET` og `KAUTH_SVC_<ID>_MICROSOFT_SECRET`, med tjeneste-id i store bokstaver og `-` som `_`.

Oppslagsrekkefølge: referanse i `_env` (satt men tom variabel gir `login_failed` for den metoden på den tjenesten, uten fallback), ellers klartekstkolonnen (overgang), ellers global `KAUTH_GOOGLE_CLIENT_SECRET`/`KAUTH_MICROSOFT_CLIENT_SECRET`.

Admin er global: tjeneste A kan peke på tjeneste Bs variabel. Det er ikke en grense mellom tjenester, bare mellom admin og resten av miljøet (andre variabler enn `KAUTH_SVC_*` kan ikke refereres).

### Flytte en klartekst-hemmelighet fra DB til `.env`

`.env` leses som systemd EnvironmentFile, så `$`, `\` og anførselstegn i verdier tolkes. Sjekk først at hemmeligheten ikke inneholder slike tegn (`sqlite3 ... | grep -c '[$\\"]'` gir 0), ellers må verdien siteres etter systemd-reglene. Verdiene skal aldri skrives til terminal, logg eller chat. Ikke bruk `set -x`, og ikke `echo` av variablene. Eksempel for `spekto` og Google; gjenta per tjeneste og metode.

```bash
cd /home/lars/kauth-go
cp -p .env .env.bak-$(date +%F)
umask 077
V=KAUTH_SVC_SPEKTO_GOOGLE_SECRET
printf '%s=%s\n' "$V" "$(sqlite3 "$KAUTH_DB_PATH" "SELECT google_client_secret FROM services WHERE id='spekto'")" >> .env
chmod 600 .env
```

Sett referansen i admin (tjenestesiden, «miljøvariabel for klienthemmelighet», verdien `KAUTH_SVC_SPEKTO_GOOGLE_SECRET`), eller med SQL:

```bash
sqlite3 "$KAUTH_DB_PATH" "UPDATE services SET google_client_secret_env='KAUTH_SVC_SPEKTO_GOOGLE_SECRET' WHERE id='spekto';"
```

Restart og sjekk oppstartsloggen:

```bash
sudo systemctl restart kauth
journalctl -u kauth --since '2 min ago' | grep 'klienthemmelighet'
```

Ingen linje «klienthemmelighet mangler» skal finnes for tjenesten. «klartekst i DB» forventes til kolonnen er nullet. Test at Google-innloggingen starter (302 til leverandøren med riktig `client_id`).

Sammenlign `.env` og kolonnen byte for byte, uten å skrive ut:

```bash
a=$(sqlite3 "$KAUTH_DB_PATH" "SELECT google_client_secret FROM services WHERE id='spekto'")
b=$(grep "^$V=" .env | cut -d= -f2-)
[ -n "$a" ] && [ "$a" = "$b" ] && echo lik || echo FORSKJELLIG
unset a b
```

Bare ved «lik» for alle verdiene, null kolonnen:

```bash
sqlite3 "$KAUTH_DB_PATH" "UPDATE services SET google_client_secret = NULL WHERE id='spekto';"
```

Restart og bekreft at «klartekst i DB» er borte. Backupen av `.env` og nattlig DB-backup holder verdiene til du er trygg. Kolonnene `google_client_secret` og `microsoft_client_secret` beholdes (tomme) til de droppes i 018.

Gammel binær ignorerer `_env`-kolonnene og leser klartekstkolonnene; er de nullet faller den tilbake til global env. Derfor nulles kolonnene sist.

### Rotere en hemmelighet

Lag ny hemmelighet i Google Cloud Console / Entra, endre verdien i `.env`, restart. Ingen DB- eller admin-endring. Gammel hemmelighet slettes hos leverandøren når innlogging er bekreftet.
