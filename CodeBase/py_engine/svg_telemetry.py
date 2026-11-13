"""Server-side orthogonal flat <svg> visual telemetry renderer (SYS.01 palette)."""

from __future__ import annotations

import html
import json
import sqlite3
from pathlib import Path


def render_svg_telemetry(db_path: str, scan_id: int | None = None, batch_id: str | None = None) -> str:
    """Generates a deterministic, zero-rounded-corner SVG chart of Dork hits vs suppressed FPs."""
    if not Path(db_path).is_file():
        return _empty_svg("DATABASE NOT INITIALIZED")

    conn = sqlite3.connect(db_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    if batch_id:
        sessions = cur.execute(
            "SELECT scan_id FROM scan_sessions WHERE batch_id = ? ORDER BY scan_id DESC",
            (batch_id,),
        ).fetchall()
    elif scan_id:
        sessions = cur.execute(
            "SELECT scan_id FROM scan_sessions WHERE scan_id = ?",
            (scan_id,),
        ).fetchall()
    else:
        latest = cur.execute(
            "SELECT batch_id FROM scan_sessions ORDER BY scan_id DESC LIMIT 1"
        ).fetchone()
        if not latest:
            conn.close()
            return _empty_svg("AWAITING FIRST AUTODORKER SCAN")
        sessions = cur.execute(
            "SELECT scan_id FROM scan_sessions WHERE batch_id = ?",
            (latest["batch_id"],),
        ).fetchall()

    scan_ids = [r["scan_id"] for r in sessions]
    if not scan_ids:
        conn.close()
        return _empty_svg("NO MATCHING SCAN SESSIONS")

    placeholders = ",".join("?" for _ in scan_ids)
    telem = cur.execute(
        f"""
        SELECT COALESCE(SUM(total_assets_crawled), 0) AS assets,
               COALESCE(SUM(raw_dork_candidates), 0) AS raw_hits,
               COALESCE(SUM(ast_fp_dropped), 0) AS ast_fp,
               COALESCE(SUM(soft404_fp_dropped), 0) AS soft404_fp,
               COALESCE(SUM(entropy_fp_dropped), 0) AS ent_fp
        FROM scan_telemetry
        WHERE scan_id IN ({placeholders})
        """,
        scan_ids,
    ).fetchone()

    sev_rows = cur.execute(
        f"""
        SELECT severity, COUNT(*) AS cnt
        FROM dork_findings
        WHERE scan_id IN ({placeholders}) AND is_suppressed_fp = 0
        GROUP BY severity
        """,
        scan_ids,
    ).fetchall()

    cat_rows = cur.execute(
        f"""
        SELECT dc.category, COUNT(*) AS cnt
        FROM dork_findings df
        JOIN dork_catalog dc ON df.dork_id = dc.dork_id
        WHERE df.scan_id IN ({placeholders}) AND df.is_suppressed_fp = 0
        GROUP BY dc.category
        ORDER BY cnt DESC
        LIMIT 5
        """,
        scan_ids,
    ).fetchall()
    conn.close()

    sev_map = {r["severity"]: r["cnt"] for r in sev_rows}
    verified_tp = sum(sev_map.values())
    ast_fp = int(telem["ast_fp"] or 0)
    soft404_fp = int(telem["soft404_fp"] or 0)
    ent_fp = int(telem["ent_fp"] or 0)
    total_fp = ast_fp + soft404_fp + ent_fp
    assets = int(telem["assets"] or 0)

    bars = [
        ("VERIFIED TP", verified_tp, "#36A19D"),
        ("CRIT / HIGH", sev_map.get("CRITICAL", 0) + sev_map.get("HIGH", 0), "#B85D78"),
        ("AST FP DROP", ast_fp, "#C9A654"),
        ("404 SIMHASH", soft404_fp, "#523B78"),
        ("ENTROPY DROP", ent_fp, "#687888"),
    ]
    max_val = max([b[1] for b in bars] + [1])

    width = 680
    height = 178
    svg_parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img" aria-label="AutoDorker Verification Telemetry">',
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="#101420" stroke="#1E2436" stroke-width="1"/>',
        '<text x="12" y="20" fill="#36A19D" font-family="JetBrains Mono, monospace" font-size="11" font-weight="700">[SYS.01 TELEMETRY // AST + SHANNON H(X) VERIFICATION FUNNEL]</text>',
        f'<text x="{width - 12}" y="20" text-anchor="end" fill="#687888" font-family="JetBrains Mono, monospace" font-size="10">ASSETS: {assets} | TP: {verified_tp} | FP DROPPED: {total_fp}</text>',
        f'<line x1="12" y1="28" x2="{width - 12}" y2="28" stroke="#1E2436" stroke-width="1"/>',
    ]

    # Left panel: 5 horizontal orthogonal telemetry bars
    y_cursor = 42
    bar_max_w = 195
    for label, val, color in bars:
        bar_w = int((val / max_val) * bar_max_w) if val > 0 else 2
        svg_parts.append(
            f'<text x="14" y="{y_cursor + 12}" fill="#DCD5C6" font-family="JetBrains Mono, monospace" font-size="10">{html.escape(label)}</text>'
        )
        svg_parts.append(
            f'<rect x="112" y="{y_cursor + 2}" width="{bar_max_w}" height="12" fill="#080C12" stroke="#1E2436" stroke-width="1"/>'
        )
        svg_parts.append(
            f'<rect x="112" y="{y_cursor + 2}" width="{bar_w}" height="12" fill="{color}"/>'
        )
        svg_parts.append(
            f'<text x="{112 + bar_max_w + 8}" y="{y_cursor + 12}" fill="{color}" font-family="JetBrains Mono, monospace" font-size="10" font-weight="700">{val:02d}</text>'
        )
        y_cursor += 25

    # Vertical divider
    svg_parts.append(f'<line x1="352" y1="34" x2="352" y2="{height - 10}" stroke="#1E2436" stroke-width="1"/>')
    svg_parts.append('<text x="364" y="48" fill="#DCD5C6" font-family="JetBrains Mono, monospace" font-size="10" font-weight="700">TOP DORK CATEGORIES (295 RULEBOOK)</text>')

    if cat_rows:
        cy = 68
        cmax = max([r["cnt"] for r in cat_rows] + [1])
        for row in cat_rows:
            cat_name = row["category"]
            short_cat = cat_name if len(cat_name) <= 28 else cat_name[:25] + "..."
            cnt = int(row["cnt"])
            cw = int((cnt / cmax) * 90) if cnt > 0 else 2
            bar_col = "#B85D78" if cat_name.startswith("[CHAIN]") else "#36A19D"
            svg_parts.append(
                f'<text x="364" y="{cy}" fill="#DCD5C6" font-family="JetBrains Mono, monospace" font-size="9.5">{html.escape(short_cat)}</text>'
            )
            svg_parts.append(
                f'<rect x="556" y="{cy - 9}" width="90" height="10" fill="#080C12" stroke="#1E2436" stroke-width="1"/>'
            )
            svg_parts.append(
                f'<rect x="556" y="{cy - 9}" width="{cw}" height="10" fill="{bar_col}"/>'
            )
            svg_parts.append(
                f'<text x="652" y="{cy}" fill="{bar_col}" font-family="JetBrains Mono, monospace" font-size="10">{cnt:02d}</text>'
            )
            cy += 21
    else:
        svg_parts.append(
            '<text x="364" y="96" fill="#687888" font-family="JetBrains Mono, monospace" font-size="10">[0 VERIFIED EXPOSURES IN CURRENT LEDGER]</text>'
        )

    svg_parts.append("</svg>")
    return "\n".join(svg_parts)


def _empty_svg(msg: str) -> str:
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 680 120" width="100%" height="120">'
        '<rect x="0" y="0" width="680" height="120" fill="#101420" stroke="#1E2436" stroke-width="1"/>'
        '<text x="340" y="54" text-anchor="middle" fill="#36A19D" font-family="JetBrains Mono, monospace" font-size="11">[SYS.01 TELEMETRY STANDBY]</text>'
        f'<text x="340" y="76" text-anchor="middle" fill="#687888" font-family="JetBrains Mono, monospace" font-size="10">{html.escape(msg)}</text>'
        "</svg>"
    )
