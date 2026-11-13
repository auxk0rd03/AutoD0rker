"""Enterprise Microsoft Word (.docx) CyberNest VIDS report generator (python-docx)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn
from docx.shared import Inches, Pt, RGBColor

from py_engine.report_md import load_scan_report_context


SEV_COLORS = {
    "CRITICAL": "B85D78",
    "HIGH": "B85D78",
    "MEDIUM": "C9A654",
    "LOW": "36A19D",
    "INFO": "523B78",
}

SLATE_DARK = "101420"
CYAN_BORDER = "36A19D"
VOID_CODE_BG = "080C12"
MUTED_BORDER = "1E2436"


def _set_cell_shading(cell: Any, hex_color: str) -> None:
    shading = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>')
    cell._tc.get_or_add_tcPr().append(shading)


def _set_cell_margins(cell: Any, top: int = 80, bottom: int = 80, left: int = 110, right: int = 110) -> None:
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement("w:tcMar")
    for side, val in (("top", top), ("bottom", bottom), ("left", left), ("right", right)):
        node = OxmlElement(f"w:{side}")
        node.set(qn("w:w"), str(val))
        node.set(qn("w:type"), "dxa")
        tcMar.append(node)
    tcPr.append(tcMar)


def _set_table_borders(table: Any, color_hex: str = MUTED_BORDER, size_eighths: str = "6") -> None:
    tblPr = table._tbl.tblPr
    borders = parse_xml(
        f'<w:tblBorders {nsdecls("w")}>'
        f'<w:top w:val="single" w:sz="{size_eighths}" w:space="0" w:color="{color_hex}"/>'
        f'<w:left w:val="single" w:sz="{size_eighths}" w:space="0" w:color="{color_hex}"/>'
        f'<w:bottom w:val="single" w:sz="{size_eighths}" w:space="0" w:color="{color_hex}"/>'
        f'<w:right w:val="single" w:sz="{size_eighths}" w:space="0" w:color="{color_hex}"/>'
        f'<w:insideH w:val="single" w:sz="4" w:space="0" w:color="{MUTED_BORDER}"/>'
        f'<w:insideV w:val="single" w:sz="4" w:space="0" w:color="{MUTED_BORDER}"/>'
        f"</w:tblBorders>"
    )
    tblPr.append(borders)


def _add_mono_box(doc: Document, code_text: str) -> None:
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    _set_table_borders(tbl, CYAN_BORDER, "6")
    cell = tbl.cell(0, 0)
    _set_cell_shading(cell, VOID_CODE_BG)
    _set_cell_margins(cell, top=100, bottom=100, left=140, right=140)
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(0)
    run = p.add_run(code_text)
    run.font.name = "JetBrains Mono"
    run.font.size = Pt(9.0)
    run.font.color.rgb = RGBColor(0xDC, 0xD5, 0xC6)


def _add_section_heading(doc: Document, title: str) -> None:
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(12)
    p.paragraph_format.space_after = Pt(4)
    pPr = p._p.get_or_add_pPr()
    pBdr = parse_xml(
        f'<w:pBdr {nsdecls("w")}><w:bottom w:val="single" w:sz="8" w:space="4" w:color="{CYAN_BORDER}"/></w:pBdr>'
    )
    pPr.append(pBdr)
    run = p.add_run(title)
    run.bold = True
    run.font.name = "Liberation Sans"
    run.font.size = Pt(13)
    run.font.color.rgb = RGBColor(0x10, 0x14, 0x20)


def write_docx_report(db_path: str, scan_id: int, out_path: str) -> Path:
    """Generates a self-contained pure OpenXML (.docx) CyberNest VIDS deliverable."""
    ctx = load_scan_report_context(db_path, scan_id)
    s = ctx["session"]
    t = ctx["telemetry"]
    actionable = ctx["actionable"]
    informational = ctx["informational"]

    doc = Document()
    for sec in doc.sections:
        sec.page_width = Inches(8.5)
        sec.page_height = Inches(11.0)
        sec.top_margin = Inches(0.75)
        sec.bottom_margin = Inches(0.75)
        sec.left_margin = Inches(0.75)
        sec.right_margin = Inches(0.75)

        hdr = sec.header.paragraphs[0]
        hrun = hdr.add_run(f"CYBERNEST LABS // AUTODORKER VIDS AUDIT REPORT  |  SCAN #{s['scan_id']}")
        hrun.font.name = "JetBrains Mono"
        hrun.font.size = Pt(8.5)
        hrun.font.color.rgb = RGBColor(0x68, 0x78, 0x88)

        ftr = sec.footer.paragraphs[0]
        frun = ftr.add_run(f"CONFIDENTIAL // AUDIT LOCK SHA-256: {ctx['db_sha256'][:24]}...")
        frun.font.name = "JetBrains Mono"
        frun.font.size = Pt(8.0)
        frun.font.color.rgb = RGBColor(0x68, 0x78, 0x88)

    normal_style = doc.styles["Normal"]
    normal_style.font.name = "Liberation Sans"
    normal_style.font.size = Pt(10.0)
    normal_style.font.color.rgb = RGBColor(0x1E, 0x24, 0x36)

    # Banner Header
    banner = doc.add_table(rows=1, cols=1)
    banner.alignment = WD_TABLE_ALIGNMENT.CENTER
    _set_table_borders(banner, CYAN_BORDER, "12")
    bcell = banner.cell(0, 0)
    _set_cell_shading(bcell, SLATE_DARK)
    _set_cell_margins(bcell, top=140, bottom=140, left=160, right=160)
    bp = bcell.paragraphs[0]
    bp.paragraph_format.space_before = Pt(0)
    bp.paragraph_format.space_after = Pt(2)
    r1 = bp.add_run("CYBERNEST LABS // AUTODORKER ENTERPRISE AUDIT REPORT\n")
    r1.bold = True
    r1.font.name = "JetBrains Mono"
    r1.font.size = Pt(13.5)
    r1.font.color.rgb = RGBColor(0x36, 0xA1, 0x9D)
    r2 = bp.add_run("SYS.01 VIDS DELIVERABLE — AST & SHANNON ENTROPY VERIFIED SURFACE ASSESSMENT")
    r2.font.name = "JetBrains Mono"
    r2.font.size = Pt(9.0)
    r2.font.color.rgb = RGBColor(0xDC, 0xD5, 0xC6)

    # Section 1: Document Control & Engagement Metadata
    _add_section_heading(doc, "1. Document Control & Engagement Metadata")
    meta_rows = [
        ("Target URL", s["target_url"]),
        ("Scan ID / Batch", f"#{s['scan_id']} (Batch {s['batch_id']} // Target Index {s['batch_index']})"),
        ("UTC Timestamp", s["created_at"]),
        ("Engagement ID", s.get("engagement_id") or "NONE (Standard Stealth)"),
        ("Scan Profile", s["scan_profile"]),
        ("Detected WAF Vendor", s.get("detected_waf_vendor", "NONE")),
        ("Surface Risk Score", f"{s['surface_risk_score']} / 100"),
        ("DB Audit Lock (SHA-256)", ctx["db_sha256"]),
    ]
    mtbl = doc.add_table(rows=len(meta_rows), cols=2)
    mtbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    _set_table_borders(mtbl, CYAN_BORDER, "6")
    for idx, (k, v) in enumerate(meta_rows):
        c0 = mtbl.cell(idx, 0)
        c1 = mtbl.cell(idx, 1)
        _set_cell_shading(c0, SLATE_DARK)
        _set_cell_margins(c0, 60, 60, 100, 100)
        _set_cell_margins(c1, 60, 60, 100, 100)
        r_k = c0.paragraphs[0].add_run(k)
        r_k.bold = True
        r_k.font.name = "JetBrains Mono"
        r_k.font.size = Pt(9.0)
        r_k.font.color.rgb = RGBColor(0xDC, 0xD5, 0xC6)
        r_v = c1.paragraphs[0].add_run(str(v))
        r_v.font.name = "JetBrains Mono"
        r_v.font.size = Pt(9.0)

    # Section 2: Executive Summary & Chained Impact
    _add_section_heading(doc, "2. Executive Summary & Chained Dork Impact Statement")
    p_exec = doc.add_paragraph(ctx["chained_summary"])
    p_exec.paragraph_format.space_after = Pt(6)
    if ctx["technologies"]:
        p_tech = doc.add_paragraph()
        rt1 = p_tech.add_run("Fingerprinted Technologies: ")
        rt1.bold = True
        p_tech.add_run(", ".join(ctx["technologies"]))

    # Section 3: AST & Shannon Entropy Telemetry
    _add_section_heading(doc, "3. AST & Shannon Entropy Verification Telemetry")
    telem_rows = [
        ("Assets Spidered (HTML / JS / Config)", f"{t.get('total_assets_crawled', s.get('pages_crawled', 0))} ({t.get('html_pages_crawled', 0)} / {t.get('js_files_crawled', 0)} / {t.get('config_files_crawled', 0)})"),
        ("Compiled Dork AST Rules Evaluated", str(s.get("dorks_evaluated", 295))),
        ("Raw Dork Candidate Matches", str(t.get("raw_dork_candidates", 0))),
        ("Gate 1 Dropped (Source AST Mismatch / JS Comments)", str(t.get("ast_fp_dropped", 0))),
        ("Gate 0 Dropped (Soft-404 via 64-bit DOM SimHash)", str(t.get("soft404_fp_dropped", 0))),
        ("Gate 2 Dropped (Low-Entropy Placeholder via H(X))", str(t.get("entropy_fp_dropped", 0))),
        ("Verified Actionable True Positives", str(len(actionable))),
    ]
    ttbl = doc.add_table(rows=len(telem_rows), cols=2)
    ttbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    _set_table_borders(ttbl, MUTED_BORDER, "6")
    for idx, (k, v) in enumerate(telem_rows):
        c0 = ttbl.cell(idx, 0)
        c1 = ttbl.cell(idx, 1)
        _set_cell_margins(c0, 50, 50, 100, 100)
        _set_cell_margins(c1, 50, 50, 100, 100)
        c0.paragraphs[0].add_run(k).font.size = Pt(9.5)
        rv = c1.paragraphs[0].add_run(v)
        rv.bold = True
        rv.font.name = "JetBrains Mono"
        rv.font.size = Pt(9.5)

    # Section 4: Technical Findings Ledger
    _add_section_heading(doc, "4. Technical Findings Ledger")
    if not actionable:
        doc.add_paragraph("Zero actionable vulnerabilities passed Gate 1 (AST) and Gate 2 (Shannon Entropy) verification.")
    else:
        for idx, f in enumerate(actionable, start=1):
            sev = f["severity"]
            card = doc.add_table(rows=5, cols=2)
            card.alignment = WD_TABLE_ALIGNMENT.CENTER
            _set_table_borders(card, CYAN_BORDER, "6")

            # Header row with cel-paint severity badge
            c_sev = card.cell(0, 0)
            c_title = card.cell(0, 1)
            _set_cell_shading(c_sev, SEV_COLORS.get(sev, "523B78"))
            _set_cell_shading(c_title, SLATE_DARK)
            _set_cell_margins(c_sev, 70, 70, 90, 90)
            _set_cell_margins(c_title, 70, 70, 100, 100)
            rsev = c_sev.paragraphs[0].add_run(f"#{idx:02d} // {sev}")
            rsev.bold = True
            rsev.font.name = "JetBrains Mono"
            rsev.font.size = Pt(9.5)
            rsev.font.color.rgb = RGBColor(0x08, 0x0C, 0x12) if sev in ("MEDIUM", "LOW") else RGBColor(0xDC, 0xD5, 0xC6)

            rtit = c_title.paragraphs[0].add_run(f"{f['category']}  [{f['cwe_id']} | CVSS {f['cvss_score']:.1f}]")
            rtit.bold = True
            rtit.font.name = "JetBrains Mono"
            rtit.font.size = Pt(9.5)
            rtit.font.color.rgb = RGBColor(0xDC, 0xD5, 0xC6)

            details = [
                ("Dork Signature", f["dork_string"]),
                ("Matched Endpoint", f["matched_endpoint"]),
                ("AST Proof & Entropy", f"{f['ast_node_type']} | Conf: {f['confidence_pct']:.1f}% | H(X): {f['entropy_bits']:.2f} bits/char | {f['cvss_vector']}"),
                ("Evidence & Remediation", f"Snippet: {f['ast_context_snippet']}\nRemediation: {f['remediation']}"),
            ]
            for r_i, (dk, dv) in enumerate(details, start=1):
                dc0 = card.cell(r_i, 0)
                dc1 = card.cell(r_i, 1)
                _set_cell_margins(dc0, 50, 50, 90, 90)
                _set_cell_margins(dc1, 50, 50, 100, 100)
                rk = dc0.paragraphs[0].add_run(dk)
                rk.bold = True
                rk.font.size = Pt(9.0)
                rv = dc1.paragraphs[0].add_run(dv)
                rv.font.name = "JetBrains Mono" if r_i in (1, 2) else "Liberation Sans"
                rv.font.size = Pt(9.0)

            p_poc_lbl = doc.add_paragraph()
            p_poc_lbl.paragraph_format.space_before = Pt(4)
            p_poc_lbl.paragraph_format.space_after = Pt(2)
            rpoc = p_poc_lbl.add_run("Stealth Browser Persona cURL PoC & Verification Steps:")
            rpoc.bold = True
            rpoc.font.size = Pt(9.5)
            _add_mono_box(doc, f["stealth_curl_poc"])

            for s_i, step in enumerate(f["repro_steps"], start=1):
                sp = doc.add_paragraph(f"{s_i}. {step}")
                sp.paragraph_format.space_before = Pt(1)
                sp.paragraph_format.space_after = Pt(1)

            doc.add_paragraph()

    # Section 5: Segregated Vendor & Informational Observations
    _add_section_heading(doc, "5. Appendix: Segregated Vendor & Informational Observations")
    doc.add_paragraph(
        f"Detected Third-Party Vendors: {', '.join(ctx['vendors']) if ctx['vendors'] else 'None detected'}"
    )
    if informational:
        itbl = doc.add_table(rows=len(informational) + 1, cols=4)
        itbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        _set_table_borders(itbl, MUTED_BORDER, "6")
        headers = ["Severity", "Category", "Endpoint", "AST / H(X)"]
        for c_i, htxt in enumerate(headers):
            hc = itbl.cell(0, c_i)
            _set_cell_shading(hc, SLATE_DARK)
            _set_cell_margins(hc, 50, 50, 80, 80)
            hr = hc.paragraphs[0].add_run(htxt)
            hr.bold = True
            hr.font.name = "JetBrains Mono"
            hr.font.size = Pt(9.0)
            hr.font.color.rgb = RGBColor(0xDC, 0xD5, 0xC6)
        for r_i, inf in enumerate(informational, start=1):
            vals = [
                inf["severity"],
                inf["category"],
                inf["matched_endpoint"],
                f"{inf['ast_node_type']} ({inf['entropy_bits']:.2f} b)",
            ]
            for c_i, val in enumerate(vals):
                cell = itbl.cell(r_i, c_i)
                _set_cell_margins(cell, 45, 45, 80, 80)
                run = cell.paragraphs[0].add_run(str(val))
                run.font.size = Pt(8.5)
    else:
        doc.add_paragraph("No segregated vendor or informational observations recorded.")

    dest = Path(out_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_symlink():
        raise PermissionError(f"CWE-377 violation: destination {dest} is a symlink")
    doc.save(str(dest))
    return dest
