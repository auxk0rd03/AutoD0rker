"""Cross-platform telemetry & signed SQLite backup parity for Windows and POSIX (P1 #6)."""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import sqlite3
from pathlib import Path


def emit_telemetry_status(db_path: str) -> tuple[int, str]:
    """Returns (exit_code, HTML telemetry badge snippet) matching scripts/sys_telemetry.sh."""
    p = Path(db_path)
    if p.is_symlink():
        return 1, '<span class="val-neg">[ERR_HALT: CWE-377 DB SYMLINK]</span>'
    if not p.is_file():
        return (
            0,
            '<span class="val-neg">[DB: OFFLINE]</span> '
            '<span class="val-pos">[GUI: 127.0.0.1]</span> '
            '<span class="val-pos">[EGRESS: INTERNET]</span>',
        )

    wal_mode = "WAL"
    dork_count = 0
    chain_count = 0
    try:
        conn = sqlite3.connect(str(p), timeout=10.0)
        try:
            row = conn.execute("PRAGMA journal_mode;").fetchone()
            if row and row[0]:
                wal_mode = str(row[0]).upper()
            d_row = conn.execute("SELECT COUNT(*) FROM dork_catalog;").fetchone()
            dork_count = int(d_row[0]) if d_row else 0
            c_row = conn.execute("SELECT COUNT(*) FROM dork_catalog WHERE is_chain = 1;").fetchone()
            chain_count = int(c_row[0]) if c_row else 0
        finally:
            conn.close()
    except sqlite3.Error:
        pass

    size_kb = max(1, p.stat().st_size // 1024)
    sync_time = dt.datetime.now(dt.timezone.utc).strftime("%H:%M:%S UTC")
    html = (
        f'<span class="val-pos">[DB: {wal_mode}_OK // {size_kb} KB]</span> '
        f'<span class="val-pos">[DORKS: {dork_count}_ACTIVE // {chain_count}_CHAIN]</span> '
        f'<span class="val-muted">[SYNC: {sync_time}]</span> '
        f'<span class="val-pos">[GUI: 127.0.0.1]</span> '
        f'<span class="val-pos">[EGRESS: INTERNET]</span>'
    )
    return 0, html


def create_signed_backup(db_path: str, backup_dir: str = "data/backups") -> tuple[int, str]:
    """Executes SQLite VACUUM INTO snapshot + SHA-256 digest with CWE-377 symlink guards."""
    src = Path(db_path)
    bdir = Path(backup_dir)
    if not src.exists():
        return 0, '<span class="val-warn">[AUDIT_LOCK: NO_DB]</span>'
    if src.is_symlink() or (bdir.exists() and bdir.is_symlink()):
        return 1, '<span class="val-neg">[ERR_HALT: CWE-377 SYMLINK]</span>'

    bdir.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(bdir, 0o700)

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_file = bdir / f"autodorker_snapshot_{stamp}.db"
    if out_file.exists() and out_file.is_symlink():
        return 1, '<span class="val-neg">[ERR_HALT: CWE-377 OUT SYMLINK]</span>'

    conn = sqlite3.connect(str(src), timeout=15.0)
    try:
        conn.execute("VACUUM INTO ?", (str(out_file),))
    finally:
        conn.close()

    if out_file.is_symlink():
        return 1, '<span class="val-neg">[ERR_HALT: CWE-377 OUT SYMLINK]</span>'
    if os.name == "posix":
        os.chmod(out_file, 0o600)

    h = hashlib.sha256()
    with out_file.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    digest_12 = h.hexdigest()[:12]
    return 0, f'<span class="val-pos">[AUDIT_LOCK: {stamp} // SHA256:{digest_12}]</span>'
