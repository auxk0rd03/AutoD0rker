#!/bin/sh
# scripts/backup_and_sign.sh — Atomic SQLite VACUUM INTO snapshot + SHA-256 Audit Lock badge
set -eu

DB_PATH="${1:-${AUTODORKER_DB_PATH:-data/autodorker_state.db}}"
BACKUP_DIR="${2:-data/backups}"
STAMP=$(date -u +"%Y%m%d_%H%M%S")
OUT_FILE="${BACKUP_DIR}/autodorker_snapshot_${STAMP}.db"

if [ ! -f "$DB_PATH" ]; then
    printf '<span class="val-warn">[AUDIT_LOCK: NO_DB]</span>\n'
    exit 0
fi

if [ -L "$DB_PATH" ] || [ -L "$BACKUP_DIR" ]; then
    printf '<span class="val-neg">[ERR_HALT: CWE-377 SYMLINK]</span>\n' >&2
    exit 1
fi

mkdir -p "$BACKUP_DIR"
chmod 0700 "$BACKUP_DIR"

if [ -L "$OUT_FILE" ]; then
    printf '<span class="val-neg">[ERR_HALT: CWE-377 OUT SYMLINK]</span>\n' >&2
    exit 1
fi

if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$DB_PATH" "VACUUM INTO '${OUT_FILE}';"
else
    PY_BIN="python3"
    if [ -x ".venv/bin/python" ]; then
        PY_BIN=".venv/bin/python"
    fi
    "$PY_BIN" -c "import sqlite3, sys; c=sqlite3.connect(sys.argv[1]); c.execute('VACUUM INTO ?', (sys.argv[2],)); c.close()" "$DB_PATH" "$OUT_FILE"
fi

chmod 0600 "$OUT_FILE"
if command -v sha256sum >/dev/null 2>&1; then
    HASH=$(sha256sum "$OUT_FILE" | cut -c1-12)
else
    HASH=$(shasum -a 256 "$OUT_FILE" | cut -c1-12)
fi

printf '<span class="val-pos">[AUDIT_LOCK: %s // SHA256:%s]</span>\n' "$STAMP" "$HASH"
