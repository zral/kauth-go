#!/bin/bash
# Døgnbackup av kauth-go SQLite-database (cron: 03:00 daglig).
# Bruker SQLite .backup-kommandoen — trygt mens kauth-go kjører (WAL-modus).

set -euo pipefail

DB_PATH="/home/lars/kauth-go/data/kauth.db"
BACKUP_DIR="/home/lars/backups/kauth-go"
KEEP_DAYS=30

mkdir -p "$BACKUP_DIR"

STAMP=$(date +%Y%m%d-%H%M)
TARGET="$BACKUP_DIR/kauth-${STAMP}.db"

if [ ! -f "$DB_PATH" ]; then
    echo "$(date -Iseconds) FEIL: $DB_PATH finnes ikke"
    exit 1
fi

# .backup gir en atomisk konsistent kopi (også under aktiv skriving)
sqlite3 "$DB_PATH" ".backup '$TARGET'"

SIZE=$(du -h "$TARGET" | cut -f1)
echo "$(date -Iseconds) Backup OK: $(basename "$TARGET") ($SIZE)"

# Rens gamle backups
find "$BACKUP_DIR" -name "kauth-*.db" -mtime +${KEEP_DAYS} -delete

COUNT=$(ls -1 "$BACKUP_DIR"/kauth-*.db 2>/dev/null | wc -l)
echo "$(date -Iseconds) Backups i $BACKUP_DIR: $COUNT"
