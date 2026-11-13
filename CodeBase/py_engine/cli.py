"""CLI subcommand dispatcher for Python AST verification, SVG telemetry, and .md/.docx exports."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from py_engine.ast_analyzer import verify_scan_findings_in_db
from py_engine.report_docx import write_docx_report
from py_engine.report_md import write_markdown_report
from py_engine.report_structured import write_jsonl_report, write_sarif_report
from py_engine.sbom_gen import generate_sbom_manifests
from py_engine.spa_hydrator import write_spa_seed
from py_engine.svg_telemetry import render_svg_telemetry
from py_engine.sys_ops import create_signed_backup, emit_telemetry_status


def _default_db() -> str:
    return os.environ.get("AUTODORKER_DB_PATH", "data/autodorker_state.db")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AutoDorker Python Engine CLI")
    parser.add_argument("--db", default=_default_db(), help="Path to SQLite3 WAL database")
    parser.add_argument("--scan-id", type=int, default=0, help="Target scan_id")
    parser.add_argument("--batch-id", default=None, help="Target batch_id")
    parser.add_argument("--harvest-dir", default=None, help="Sandboxed temporary harvest directory")
    parser.add_argument("--out", default=None, help="Output file path")
    parser.add_argument("--out-dir", default=None, help="Output directory for --export-all")
    parser.add_argument("--target", default=None, help="Target URL for --hydrate-spa")
    parser.add_argument("--proxy", default=None, help="Loopback SSRF proxy URL for --hydrate-spa")
    parser.add_argument("--backup-dir", default="data/backups", help="Backup directory for --backup-sign")

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--verify-ast", action="store_true", help="Run Stage-2 esprima/pyyaml/lxml AST verification")
    mode.add_argument("--svg", action="store_true", help="Emit server-side orthogonal SVG telemetry fragment")
    mode.add_argument("--export-md", action="store_true", help="Compile Bug Bounty Markdown (.md) report")
    mode.add_argument("--export-docx", action="store_true", help="Compile Enterprise Word (.docx) report")
    mode.add_argument("--export-sarif", action="store_true", help="Compile SARIF v2.1.0 report")
    mode.add_argument("--export-jsonl", action="store_true", help="Compile JSON-Lines (.jsonl) stream report")
    mode.add_argument("--export-all", action="store_true", help="Compile .md, .docx, .sarif, and .jsonl into --out-dir")
    mode.add_argument("--hydrate-spa", action="store_true", help="Run optional Stage-0 headless SPA hydrator")
    mode.add_argument("--telemetry-status", action="store_true", help="Emit cross-platform topbar telemetry HTML fragment")
    mode.add_argument("--backup-sign", action="store_true", help="Create VACUUM INTO DB backup with SHA-256 audit lock")
    mode.add_argument("--generate-sbom", action="store_true", help="Regenerate CycloneDX, SPDX, and Markdown SBOMs")

    args = parser.parse_args(argv)

    if args.verify_ast:
        if args.scan_id <= 0:
            print(json.dumps({"error": "--scan-id required"}), file=sys.stderr)
            return 1
        res = verify_scan_findings_in_db(args.db, args.scan_id, args.harvest_dir)
        print(json.dumps({"status": "OK", "scan_id": args.scan_id, **res}))
        return 0

    if args.svg:
        svg = render_svg_telemetry(args.db, scan_id=args.scan_id or None, batch_id=args.batch_id)
        print(svg)
        return 0

    if args.export_md:
        if args.scan_id <= 0 or not args.out:
            print(json.dumps({"error": "--scan-id and --out required"}), file=sys.stderr)
            return 1
        out = write_markdown_report(args.db, args.scan_id, args.out)
        print(json.dumps({"status": "OK", "markdown": str(out)}))
        return 0

    if args.export_docx:
        if args.scan_id <= 0 or not args.out:
            print(json.dumps({"error": "--scan-id and --out required"}), file=sys.stderr)
            return 1
        out = write_docx_report(args.db, args.scan_id, args.out)
        print(json.dumps({"status": "OK", "docx": str(out)}))
        return 0

    if args.export_sarif:
        if args.scan_id <= 0 or not args.out:
            print(json.dumps({"error": "--scan-id and --out required"}), file=sys.stderr)
            return 1
        out = write_sarif_report(args.db, args.scan_id, args.out)
        print(json.dumps({"status": "OK", "sarif": str(out)}))
        return 0

    if args.export_jsonl:
        if args.scan_id <= 0 or not args.out:
            print(json.dumps({"error": "--scan-id and --out required"}), file=sys.stderr)
            return 1
        out = write_jsonl_report(args.db, args.scan_id, args.out)
        print(json.dumps({"status": "OK", "jsonl": str(out)}))
        return 0

    if args.export_all:
        if args.scan_id <= 0 or not args.out_dir:
            print(json.dumps({"error": "--scan-id and --out-dir required"}), file=sys.stderr)
            return 1
        out_root = Path(args.out_dir)
        if out_root.is_symlink():
            print(json.dumps({"error": "CWE-377 symlink blocked"}), file=sys.stderr)
            return 1
        out_root.mkdir(parents=True, exist_ok=True)
        md_path = out_root / f"autodorker_triage_scan_{args.scan_id}.md"
        docx_path = out_root / f"AutoDorker_Enterprise_Report_{args.scan_id}.docx"
        sarif_path = out_root / f"autodorker_scan_{args.scan_id}.sarif"
        jsonl_path = out_root / f"autodorker_scan_{args.scan_id}.jsonl"
        write_markdown_report(args.db, args.scan_id, str(md_path))
        write_docx_report(args.db, args.scan_id, str(docx_path))
        write_sarif_report(args.db, args.scan_id, str(sarif_path))
        write_jsonl_report(args.db, args.scan_id, str(jsonl_path))
        print(
            json.dumps(
                {
                    "status": "OK",
                    "markdown": str(md_path),
                    "docx": str(docx_path),
                    "sarif": str(sarif_path),
                    "jsonl": str(jsonl_path),
                }
            )
        )
        return 0

    if args.hydrate_spa:
        if not args.target or not args.out:
            print(json.dumps({"error": "--target and --out required"}), file=sys.stderr)
            return 1
        payload = write_spa_seed(args.target, args.out, proxy_url=args.proxy)
        print(
            json.dumps(
                {
                    "status": "OK",
                    "hydrated": bool(payload.get("hydrated", False)),
                    "engine": payload.get("hydrator_engine", "unavailable"),
                    "xhr_count": len(payload.get("xhr_urls", [])),
                    "out": args.out,
                }
            )
        )
        return 0

    if args.telemetry_status:
        code, html = emit_telemetry_status(args.db)
        print(html)
        return code

    if args.backup_sign:
        code, html = create_signed_backup(args.db, args.backup_dir)
        if code != 0:
            print(html, file=sys.stderr)
        else:
            print(html)
        return code

    if args.generate_sbom:
        codebase_root = Path(__file__).resolve().parent.parent
        paths = generate_sbom_manifests(codebase_root)
        print(json.dumps({"status": "OK", **{k: str(v) for k, v in paths.items()}}))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
