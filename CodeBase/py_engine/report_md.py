"""CyberNest VIDS Bug Bounty Markdown (.md) report generator with Stealth cURL PoCs."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any


STEALTH_CURL_HEADERS_BLOCK = (
    '  -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" \\\n'
    '  -H "Sec-Ch-Ua: \\"Chromium\\";v=\\"124\\", \\"Google Chrome\\";v=\\"124\\", \\"Not-A.Brand\\";v=\\"99\\"" \\\n'
    '  -H "Sec-Ch-Ua-Mobile: ?0" \\\n'
    '  -H "Sec-Ch-Ua-Platform: \\"Linux\\"" \\\n'
    '  -H "Sec-Fetch-Dest: document" \\\n'
    '  -H "Sec-Fetch-Mode: navigate" \\\n'
    '  -H "Sec-Fetch-Site: none" \\\n'
    '  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \\\n'
    '  -H "Accept-Language: en-US,en;q=0.9"'
)


def ensure_stealth_curl_poc(curl_cmd: str, endpoint: str) -> str:
    """Guarantees every cURL PoC includes Chrome 124 L7 Client Hints."""
    if "Sec-Ch-Ua" in curl_cmd and "Mozilla/5.0" in curl_cmd:
        return curl_cmd
    safe_ep = endpoint.replace('"', "%22")
    return f'curl -s -i "{safe_ep}" \\\n{STEALTH_CURL_HEADERS_BLOCK}'


def compute_db_sha256(db_path: str) -> str:
    p = Path(db_path)
    if not p.is_file() or p.is_symlink():
        return "UNAVAILABLE"
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_scan_report_context(db_path: str, scan_id: int) -> dict[str, Any]:
    """Loads scan metadata, telemetry, verified findings, and vendor/INFO observations."""
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    session = cur.execute(
        "SELECT * FROM scan_sessions WHERE scan_id = ?",
        (scan_id,),
    ).fetchone()
    if not session:
        conn.close()
        raise ValueError(f"Scan ID {scan_id} not found in {db_path}")

    telem = cur.execute(
        "SELECT * FROM scan_telemetry WHERE scan_id = ?",
        (scan_id,),
    ).fetchone()

    rows = cur.execute(
        """
        SELECT df.*, dc.category, dc.is_chain, dc.dork_string, dc.notes
        FROM dork_findings df
        JOIN dork_catalog dc ON df.dork_id = dc.dork_id
        WHERE df.scan_id = ?
        ORDER BY
          CASE df.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END,
          df.finding_id ASC
        """,
        (scan_id,),
    ).fetchall()

    endpoints = cur.execute(
        "SELECT endpoint_url, source_type, http_status, is_vendor_asset FROM harvested_endpoints WHERE scan_id = ?",
        (scan_id,),
    ).fetchall()
    conn.close()

    actionable: list[dict[str, Any]] = []
    informational: list[dict[str, Any]] = []
    for r in rows:
        item = dict(r)
        item["stealth_curl_poc"] = ensure_stealth_curl_poc(
            item.get("stealth_curl_poc", ""), item.get("matched_endpoint", "")
        )
        item["entropy_bits"] = round(float(item.get("shannon_entropy_bps", 0)) / 100.0, 2)
        item["cvss_score"] = round(float(item.get("cvss_score_bps", 0)) / 100.0, 1)
        item["confidence_pct"] = round(float(item.get("confidence_bps", 0)) / 100.0, 1)
        item["repro_steps"] = _build_repro_steps(item)
        if item["severity"] == "INFO" or item["is_suppressed_fp"]:
            informational.append(item)
        else:
            actionable.append(item)

    telem_dict = dict(telem) if telem else {}
    vendors = json.loads(telem_dict.get("vendor_observations_json", "[]") or "[]")
    technologies = json.loads(telem_dict.get("technologies_json", "[]") or "[]")

    session_dict = dict(session)
    chained_summary = build_chained_impact_statement(
        session_dict["target_url"],
        actionable,
        int(session_dict["surface_risk_score"]),
    )

    return {
        "session": session_dict,
        "telemetry": telem_dict,
        "actionable": actionable,
        "informational": informational,
        "vendors": vendors,
        "technologies": technologies,
        "endpoints": [dict(e) for e in endpoints],
        "chained_summary": chained_summary,
        "db_sha256": compute_db_sha256(db_path),
    }


def _build_repro_steps(finding: dict[str, Any]) -> list[str]:
    ep = finding.get("matched_endpoint", "")
    node = finding.get("ast_node_type", "DOM_TITLE")
    dork = finding.get("dork_string", "")
    return [
        f"Execute the Stealth Browser Persona cURL probe against `{ep}` preserving Chrome 124 L7 Client Hints.",
        f"Inspect the HTTP response structure (`{node}`) against the compiled Dork AST signature `{dork}`.",
        f"Confirm exposure authenticity via snippet `{finding.get('ast_context_snippet', '')}` and Shannon entropy H(X)={finding.get('entropy_bits', 0.0):.2f} bits/char.",
    ]


def build_chained_impact_statement(target_url: str, actionable: list[dict[str, Any]], risk_score: int) -> str:
    if not actionable:
        return (
            f"AutoDorker evaluated all 295 compiled DorkSet AST rules against `{target_url}`. "
            f"Zero actionable exposures passed Gate 1 (Source AST) and Gate 2 (Shannon Entropy H(X)) verification, "
            f"yielding a Surface Risk Score of {risk_score}/100."
        )

    chain_cats = [f["category"] for f in actionable if f.get("is_chain")]
    sevs = {f["severity"] for f in actionable}
    has_creds = any(f["cwe_id"] == "CWE-798" for f in actionable)
    has_cfg = any(f["cwe_id"] == "CWE-538" for f in actionable)
    has_login = any(f["cwe_id"] == "CWE-287" for f in actionable)

    chain_narrative = (
        f"AutoDorker verified {len(actionable)} actionable finding(s) against `{target_url}` "
        f"(Surface Risk Score: {risk_score}/100; highest severities: {', '.join(sorted(sevs))}). "
    )
    if chain_cats:
        chain_narrative += f"Triggered [CHAIN] categories include {', '.join(sorted(set(chain_cats)))}. "
    if has_creds and (has_cfg or has_login):
        chain_narrative += (
            "Chained Impact: Exposed configuration/directory artifacts combined with high-entropy "
            "credentials and discovered authentication portals create an elevated privilege-escalation "
            "or unauthorized origin-access attack path."
        )
    elif has_cfg and has_login:
        chain_narrative += (
            "Chained Impact: Exposed directory listings and configuration files provide reconnaissance "
            "metadata directly targeting discovered authentication endpoints."
        )
    else:
        chain_narrative += (
            "Each finding was structurally verified via DOM/JS/Config AST inspection and calibrated "
            "Shannon entropy thresholds to eliminate keyword and Soft-404 false positives."
        )
    return chain_narrative


def render_markdown_report(ctx: dict[str, Any]) -> str:
    s = ctx["session"]
    t = ctx["telemetry"]
    actionable = ctx["actionable"]
    informational = ctx["informational"]
    vendors = ctx["vendors"]
    technologies = ctx["technologies"]

    ast_drop = int(t.get("ast_fp_dropped", 0) or 0)
    s404_drop = int(t.get("soft404_fp_dropped", 0) or 0)
    ent_drop = int(t.get("entropy_fp_dropped", 0) or 0)
    total_assets = int(t.get("total_assets_crawled", s.get("pages_crawled", 0)) or 0)

    lines: list[str] = [
        "# CyberNest Labs // AutoDorker Vulnerability Identification & Defense Specification (VIDS)",
        "",
        "## 1. Document Control & Engagement Metadata",
        "",
        "| Field | Value |",
        "| :--- | :--- |",
        f"| **Target URL** | `{s['target_url']}` |",
        f"| **Scan ID / Batch** | `#{s['scan_id']}` (`{s['batch_id']}` / Index `{s['batch_index']}`) |",
        f"| **UTC Timestamp** | `{s['created_at']}` |",
        f"| **Engagement ID** | `{s.get('engagement_id') or 'NONE (Standard Stealth)'}` |",
        f"| **Scan Profile** | `{s['scan_profile']}` |",
        f"| **Detected WAF Vendor** | `{s.get('detected_waf_vendor', 'NONE')}` |",
        f"| **Surface Risk Score** | `{s['surface_risk_score']}/100` |",
        f"| **DB Audit Lock (SHA-256)** | `{ctx['db_sha256']}` |",
        "",
        "## 2. Executive Summary & Chained Dork Impact Statement",
        "",
        ctx["chained_summary"],
        "",
        f"**Detected Stack Technologies**: {', '.join(technologies) if technologies else 'None fingerprinted'}",
        "",
        "## 3. AST & Shannon Entropy Verification Telemetry",
        "",
        "| Telemetry Metric | Observed Count |",
        "| :--- | ---: |",
        f"| Total Assets Spidered (HTML / JS / Config) | {total_assets} ({t.get('html_pages_crawled', 0)} / {t.get('js_files_crawled', 0)} / {t.get('config_files_crawled', 0)}) |",
        f"| Dork AST Rules Evaluated | {s.get('dorks_evaluated', 295)} |",
        f"| Raw Dork AST Candidate Hits | {t.get('raw_dork_candidates', 0)} |",
        f"| Gate 1 Dropped (Source AST Mismatch / JS Comments) | {ast_drop} |",
        f"| Gate 0 Dropped (Soft-404 via 64-bit DOM SimHash) | {s404_drop} |",
        f"| Gate 2 Dropped (Low-Entropy Placeholder via H(X)) | {ent_drop} |",
        f"| Verified Actionable Findings | {len(actionable)} |",
        "",
        "## 4. Technical Findings Ledger",
        "",
    ]

    if not actionable:
        lines.append("_No actionable dork exposures passed Gate 1 (AST) and Gate 2 (Shannon Entropy) verification._\n")
    else:
        for idx, f in enumerate(actionable, start=1):
            lines.extend([
                f"### Finding #{idx:02d} — [{f['severity']}] {f['category']}",
                "",
                f"- **Dork Signature**: `{f['dork_string']}`",
                f"- **Matched Endpoint**: `{f['matched_endpoint']}`",
                f"- **Classification**: `{f['cwe_id']}` | **CVSS v3.1**: `{f['cvss_score']:.1f}` (`{f['cvss_vector']}`)",
                f"- **AST Structural Proof**: `{f['ast_node_type']}` | **Confidence**: `{f['confidence_pct']:.1f}%`",
                f"- **Shannon Entropy H(X)**: `{f['entropy_bits']:.2f} bits/char`",
                f"- **Evidence Snippet**: `{f['ast_context_snippet']}`",
                "",
                "**Stealth Browser Persona `curl` PoC**:",
                "```bash",
                f["stealth_curl_poc"],
                "```",
                "",
                "**Step-by-Step Reproduction Guide**:",
            ])
            for step_i, step in enumerate(f["repro_steps"], start=1):
                lines.append(f"{step_i}. {step}")
            lines.extend([
                "",
                f"**Engineering Remediation**: {f['remediation']}",
                "",
                "---",
                "",
            ])

    lines.extend([
        "## 5. Appendix: Segregated Vendor & Informational Observations",
        "",
        "Third-party analytics/WAF telemetry and Shadow-Mode low-entropy items are segregated here to prevent risk score inflation:",
        "",
        f"- **Third-Party Vendors Detected**: {', '.join(vendors) if vendors else 'None detected'}",
        "",
    ])

    if informational:
        lines.append("| Severity | Category | Endpoint | AST Node | H(X) | Note |")
        lines.append("| :--- | :--- | :--- | :--- | ---: | :--- |")
        for inf in informational:
            lines.append(
                f"| {inf['severity']} | {inf['category']} | `{inf['matched_endpoint']}` | `{inf['ast_node_type']}` | {inf['entropy_bits']:.2f} | `{inf['ast_context_snippet']}` |"
            )
    else:
        lines.append("_No segregated vendor or informational observations recorded._")

    lines.append("")
    return "\n".join(lines)


def write_markdown_report(db_path: str, scan_id: int, out_path: str) -> Path:
    ctx = load_scan_report_context(db_path, scan_id)
    md_text = render_markdown_report(ctx)
    dest = Path(out_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_symlink():
        raise PermissionError(f"CWE-377 violation: destination {dest} is a symlink")
    dest.write_text(md_text, encoding="utf-8")
    return dest
