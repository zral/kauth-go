#!/bin/bash
# Kjører migrasjonene (010 og 011) mot en kopi av en kauth-database og skriver en rapport
# uten e-postadresser. Kilden åpnes bare lesende (sqlite3 -readonly .backup).
#
# Bruk: scripts/identity-preflight.sh <kilde.db> [scratch-katalog]
set -euo pipefail
umask 077

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "bruk: $0 <kilde.db> [scratch-katalog]" >&2
    exit 2
fi
SRC="$1"
[ -f "$SRC" ] || { echo "finner ikke $SRC" >&2; exit 2; }

case "$SRC${2:-}" in
    *"'"*) echo "stier med ' støttes ikke" >&2; exit 2 ;;
esac

if [ $# -eq 2 ]; then
    mkdir -p "$2"
    SCRATCH=$(cd "$2" && pwd)
    case "$SCRATCH" in *"'"*) echo "stier med ' støttes ikke" >&2; exit 2 ;; esac
    KEEP=1
else
    SCRATCH=$(mktemp -d)
    KEEP=0
    # Kopien inneholder alle brukere og hemmeligheter fra kilden.
    trap 'rm -rf "$SCRATCH"' EXIT
fi
COPY="$SCRATCH/copy.db"
rm -f "$COPY" "$COPY-wal" "$COPY-shm"

sqlite3 -readonly "$SRC" ".backup '$COPY'"
echo "kopi: $COPY"

cd "$(dirname "$0")/.."
rc=0
CGO_ENABLED=0 go run ./scripts/identity-preflight "$COPY" || rc=$?
if [ "$KEEP" = 1 ]; then
    echo "HUSK: slett kopien (inneholder produksjonsdata): rm -rf '$SCRATCH'"
fi
exit $rc
