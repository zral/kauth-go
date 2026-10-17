#!/bin/bash
# Restore-test: starter kauth mot en kopi av en backup i en midlertidig mappe og
# verifiserer oppstart og radantall. Rører aldri prod-DB, .env eller port 8083.
# Skriver bare antall og statuskoder, aldri innhold (backupen har hemmeligheter).

set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

die() { echo "FEIL: $*" >&2; exit 1; }

[ $# -ge 1 ] && [ -n "${1:-}" ] || die "bruk: restore-test.sh <backup.db> [port]"
SRC_ARG="$1"
PORT="${2:-8097}"

[[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1024 ] && [ "$PORT" -le 65535 ] || die "ugyldig port"
[ "$PORT" != "8083" ] || die "port 8083 er prod og nektes"

[ -f "$SRC_ARG" ] || die "backupfilen finnes ikke"
SRC="$(realpath "$SRC_ARG")"

# Prod-stien leses bare som sti (én linje), aldri resten av .env.
# Uten leselig sti i .env faller vi tilbake til standardplasseringen.
PROD_DB=""
if [ -f "$ROOT/.env" ]; then
    PROD_DB="$(grep '^KAUTH_DB_PATH=' "$ROOT/.env" | head -n1 | cut -d= -f2- || true)"
fi
PROD_DB="${PROD_DB:-./data/kauth.db}"
case "$PROD_DB" in /*) ;; *) PROD_DB="$ROOT/$PROD_DB" ;; esac
PROD_REAL="$(realpath -m "$PROD_DB")"
DATA_REAL="$(realpath -m "$ROOT/data")"

[ "$SRC" != "$PROD_REAL" ] || die "kilden er prod-DB; bruk en backup"
case "$SRC/" in "$DATA_REAL"/*) die "kilden ligger i data/; bruk en backup" ;; esac

[ "$(sqlite3 -readonly "$SRC" 'pragma integrity_check' 2>/dev/null || true)" = "ok" ] \
    || die "integrity_check ga ikke ok"

# Porten må være ledig; ellers kunne vi testet en annen prosess.
if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
    die "port $PORT er i bruk"
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/kauth-restore.XXXXXX")"
PID=""
cleanup() {
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        kill "$PID" 2>/dev/null || true
        for _ in $(seq 1 50); do kill -0 "$PID" 2>/dev/null || break; sleep 0.1; done
        kill -9 "$PID" 2>/dev/null || true
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

sqlite3 -readonly "$SRC" ".backup '$TMP/kauth.db'"

openssl genpkey -algorithm RSA -out "$TMP/priv.pem" -pkeyopt rsa_keygen_bits:2048 2>/dev/null
openssl pkey -in "$TMP/priv.pem" -pubout -out "$TMP/pub.pem" 2>/dev/null

# Alltid en kopi i tmp, så prod-binæren aldri brukes direkte.
if [ -x "$ROOT/bin/kauth-arm64" ]; then
    cp "$ROOT/bin/kauth-arm64" "$TMP/kauth"
else
    (cd "$ROOT" && CGO_ENABLED=0 go build -o "$TMP/kauth" ./cmd/kauth)
fi

STATE_SECRET="$(openssl rand -base64 48)"
ISSUER="http://127.0.0.1:$PORT"

# Bare eksplisitte variabler; ingen arv fra skall eller .env.
env -i \
    PATH="$PATH" HOME="$TMP" \
    KAUTH_DB_PATH="$TMP/kauth.db" \
    KAUTH_HTTP_PORT="$PORT" KAUTH_HTTP_ADDR=127.0.0.1 \
    KAUTH_ISSUER="$ISSUER" KAUTH_BASE_URL="$ISSUER" \
    KAUTH_PRIVATE_KEY_PATH="$TMP/priv.pem" KAUTH_PUBLIC_KEY_PATH="$TMP/pub.pem" \
    KAUTH_OIDC_STATE_SECRET="$STATE_SECRET" \
    KAUTH_SMTP_MOCK=true KAUTH_INSECURE_COOKIES=true \
    KAUTH_LOG_LEVEL=warn \
    "$TMP/kauth" >"$TMP/kauth.log" 2>&1 &
PID=$!

code() { curl -s -o "${2:-/dev/null}" -w '%{http_code}' --max-time 5 "$ISSUER$1" || true; }

READY=0
for _ in $(seq 1 60); do
    kill -0 "$PID" 2>/dev/null || die "kauth avsluttet under oppstart (exit uten svar)"
    if [ "$(code /.well-known/openid-configuration)" = "200" ]; then READY=1; break; fi
    sleep 0.5
done
[ "$READY" = 1 ] || die "kauth ble ikke klar innen 30 s"

FAIL=0
D="$(code /.well-known/openid-configuration)"
J="$(code /.well-known/jwks.json "$TMP/jwks.json")"
L="$(code /login)"
KEYS="$(grep -o '"kid"' "$TMP/jwks.json" 2>/dev/null | wc -l)"
echo "status discovery=$D jwks=$J login=$L jwks_nøkler=$KEYS"
[ "$D" = "200" ] && [ "$J" = "200" ] && [ "$L" = "200" ] && [ "$KEYS" -ge 1 ] || FAIL=1

count() { sqlite3 -readonly "$1" "select count(*) from $2" 2>/dev/null || echo "?"; }
for t in users services user_identities; do
    A="$(count "$SRC" "$t")"; B="$(count "$TMP/kauth.db" "$t")"
    if [ "$A" = "$B" ] && [ "$A" != "?" ]; then s=ok; else s=AVVIK; FAIL=1; fi
    echo "rader $t: kilde=$A restaurert=$B $s"
done

GA="$(sqlite3 -readonly "$SRC" 'select max(version_id) from goose_db_version' 2>/dev/null || echo 0)"
GB="$(sqlite3 -readonly "$TMP/kauth.db" 'select max(version_id) from goose_db_version' 2>/dev/null || echo 0)"
if [ "${GB:-0}" -ge "${GA:-0}" ]; then s=ok; else s=AVVIK; FAIL=1; fi
echo "goose maks: kilde=$GA restaurert=$GB $s"

if [ "$FAIL" = 0 ]; then echo "RESTORE-TEST OK"; else echo "RESTORE-TEST FEILET"; exit 1; fi
