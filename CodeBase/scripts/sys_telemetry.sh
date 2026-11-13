#!/bin/sh
# scripts/sys_telemetry.sh — Emits SYS.01 top status bar HTML fragment (POSIX sh)
set -eu

DB_PATH="${1:-${AUTODORKER_DB_PATH:-data/autodorker_state.db}}"
if [ ! -f "$DB_PATH" ]; then
    printf '<span class="val-neg">[DB: OFFLINE]</span> <span class="val-pos">[LOOPBACK: 127.0.0.1]</span>\n'
    exit 0
fi

if [ -L "$DB_PATH" ]; then
    printf '<span class="val-neg">[ERR_HALT: CWE-377 DB SYMLINK]</span>\n'
    exit 1
fi

PY_BIN="python3"
if [ -x ".venv/bin/python" ]; then
    PY_BIN=".venv/bin/python"
fi

if command -v sqlite3 >/dev/null 2>&1; then
    WAL_MODE=$(sqlite3 "$DB_PATH" "PRAGMA journal_mode;" | tr '[:lower:]' '[:upper:]')
    DORK_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM dork_catalog;" 2>/dev/null || printf '0')
    CHAIN_COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM dork_catalog WHERE is_chain = 1;" 2>/dev/null || printf '0')
else
    STATS=$("$PY_BIN" -c "import sqlite3, sys; c=sqlite3.connect(sys.argv[1]); w=c.execute('PRAGMA journal_mode;').fetchone()[0].upper(); d=c.execute('SELECT COUNT(*) FROM dork_catalog').fetchone()[0]; ch=c.execute('SELECT COUNT(*) FROM dork_catalog WHERE is_chain=1').fetchone()[0]; print(f'{w} {d} {ch}')" "$DB_PATH" 2>/dev/null || printf 'WAL 0 0')
    WAL_MODE=$(printf '%s' "$STATS" | awk '{print $1}')
    DORK_COUNT=$(printf '%s' "$STATS" | awk '{print $2}')
    CHAIN_COUNT=$(printf '%s' "$STATS" | awk '{print $3}')
fi

DB_SIZE_KB=$(du -k "$DB_PATH" | awk '{print $1}')
SYNC_TIME=$(date -u +"%H:%M:%S UTC")

printf '<span class="val-pos">[DB: %s_OK // %s KB]</span> <span class="val-pos">[DORKS: %s_ACTIVE // %s_CHAIN]</span> <span class="val-muted">[SYNC: %s]</span> <span class="val-pos">[LOOPBACK: 127.0.0.1]</span>\n' \
    "$WAL_MODE" "$DB_SIZE_KB" "$DORK_COUNT" "$CHAIN_COUNT" "$SYNC_TIME"
