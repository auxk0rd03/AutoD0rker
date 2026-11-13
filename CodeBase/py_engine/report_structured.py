"""Structured machine-readable report exporters: SARIF v2.1.0 & JSON-Lines (P1 #4)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from py_engine.report_md import load_scan_report_context

SARIF_SCHEMA_URL = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)


def _sarif_level(severity: str, is_suppressed: bool) -> str:
    if is_suppressed:
        return "note"
    sev = severity.upper()
    if sev in {"CRITICAL", "HIGH"}:
        return "error"
    if sev == "MEDIUM":
        return "warning"
    return "note"


def _assert_safe_output_dest(out_path: str) -> Path:
    dest = Path(out_path)
    if dest.exists() and dest.is_symlink():
        raise PermissionError(f"CWE-377 violation: destination {dest} is a symlink")
    if dest.parent.exists() and dest.parent.is_symlink():
        raise PermissionError(f"CWE-377 violation: parent dir {dest.parent} is a symlink")
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_symlink():
        raise PermissionError(f"CWE-377 violation: destination {dest} is a symlink")
    return dest


def render_sarif_report(ctx: dict[str, Any]) -> dict[str, Any]:
    """Builds a SARIF v2.1.0 JSON dictionary from scan report context."""
    session = ctx["session"]
    telemetry = ctx.get("telemetry", {})
    all_findings = list(ctx.get("actionable", [])) + list(ctx.get("informational", []))

    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in all_findings:
        rule_id = f"AD-{int(f.get('dork_id', 0)):03d}"
        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": str(f.get("category", "AutoDorkerRule")),
                "shortDescription": {"text": f"{f.get('category', '')} ({f.get('cwe_id', '')})"},
                "fullDescription": {"text": f"Dork signature: {f.get('dork_string', '')}"},
                "help": {"text": str(f.get("remediation", ""))},
                "properties": {
                    "category": f.get("category", ""),
                    "is_chain": bool(f.get("is_chain", 0)),
                    "cwe": f.get("cwe_id", ""),
                    "default_severity": f.get("severity", "INFO"),
                },
            }

        is_suppressed = bool(f.get("is_suppressed_fp", 0))
        res_entry: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _sarif_level(str(f.get("severity", "INFO")), is_suppressed),
            "message": {
                "text": (
                    f"[{f.get('severity', 'INFO')}] {f.get('category', '')} via {f.get('ast_node_type', '')}: "
                    f"{f.get('ast_context_snippet', '')}"
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": str(f.get("matched_endpoint", "")),
                        }
                    }
                }
            ],
            "partialFingerprints": {
                "exactDedupHash": str(f.get("exact_dedup_hash", "")),
            },
            "properties": {
                "finding_id": int(f.get("finding_id", 0)),
                "severity": f.get("severity", "INFO"),
                "cwe_id": f.get("cwe_id", ""),
                "cvss_vector": f.get("cvss_vector", ""),
                "cvss_score": float(f.get("cvss_score", 0.0)),
                "shannon_entropy_bits": float(f.get("entropy_bits", 0.0)),
                "confidence_pct": float(f.get("confidence_pct", 0.0)),
                "ast_node_type": f.get("ast_node_type", ""),
                "ast_context_snippet": f.get("ast_context_snippet", ""),
                "stealth_curl_poc": f.get("stealth_curl_poc", ""),
                "remediation": f.get("remediation", ""),
                "is_chain": bool(f.get("is_chain", 0)),
                "is_suppressed_fp": is_suppressed,
            },
        }
        if is_suppressed:
            res_entry["suppressions"] = [
                {
                    "kind": "inSource",
                    "justification": "Low-entropy or third-party shadow-mode informational observation",
                }
            ]
        results.append(res_entry)

    return {
        "$schema": SARIF_SCHEMA_URL,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AutoDorker",
                        "semanticVersion": "2.0.0",
                        "organization": "CyberNest Labs",
                        "informationUri": "https://github.com/auxk0rd03/AutoD0rker",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": session.get("status") != "FAILED",
                        "properties": {
                            "scan_id": int(session.get("scan_id", 0)),
                            "batch_id": session.get("batch_id", ""),
                            "target_url": session.get("target_url", ""),
                            "scan_profile": session.get("scan_profile", ""),
                            "surface_risk_score": int(session.get("surface_risk_score", 0)),
                            "detected_waf_vendor": session.get("detected_waf_vendor", "NONE"),
                            "pages_crawled": int(session.get("pages_crawled", 0)),
                            "dorks_evaluated": int(session.get("dorks_evaluated", 0)),
                            "ast_fp_dropped": int(telemetry.get("ast_fp_dropped", 0)),
                            "soft404_fp_dropped": int(telemetry.get("soft404_fp_dropped", 0)),
                            "entropy_fp_dropped": int(telemetry.get("entropy_fp_dropped", 0)),
                            "db_sha256": ctx.get("db_sha256", ""),
                        },
                    }
                ],
                "results": results,
            }
        ],
    }


def render_jsonl_report(ctx: dict[str, Any]) -> str:
    """Renders scan session, findings, and harvested endpoints as NDJSON / JSON-Lines."""
    session = ctx["session"]
    telemetry = ctx.get("telemetry", {})
    all_findings = list(ctx.get("actionable", [])) + list(ctx.get("informational", []))
    endpoints = list(ctx.get("endpoints", []))

    lines: list[str] = []
    header = {
        "record_type": "scan_session",
        "scan_id": int(session.get("scan_id", 0)),
        "batch_id": session.get("batch_id", ""),
        "target_url": session.get("target_url", ""),
        "scan_profile": session.get("scan_profile", ""),
        "status": session.get("status", ""),
        "surface_risk_score": int(session.get("surface_risk_score", 0)),
        "detected_waf_vendor": session.get("detected_waf_vendor", "NONE"),
        "pages_crawled": int(session.get("pages_crawled", 0)),
        "dorks_evaluated": int(session.get("dorks_evaluated", 0)),
        "verified_findings_count": len(ctx.get("actionable", [])),
        "informational_count": len(ctx.get("informational", [])),
        "harvested_endpoints_count": len(endpoints),
        "telemetry": {
            "html_pages_crawled": int(telemetry.get("html_pages_crawled", 0)),
            "js_files_crawled": int(telemetry.get("js_files_crawled", 0)),
            "config_files_crawled": int(telemetry.get("config_files_crawled", 0)),
            "ast_fp_dropped": int(telemetry.get("ast_fp_dropped", 0)),
            "soft404_fp_dropped": int(telemetry.get("soft404_fp_dropped", 0)),
            "entropy_fp_dropped": int(telemetry.get("entropy_fp_dropped", 0)),
        },
        "db_sha256": ctx.get("db_sha256", ""),
    }
    lines.append(json.dumps(header, separators=(",", ":")))

    for f in all_findings:
        rec = {
            "record_type": "finding",
            "scan_id": int(session.get("scan_id", 0)),
            "finding_id": int(f.get("finding_id", 0)),
            "dork_id": int(f.get("dork_id", 0)),
            "exact_dedup_hash": f.get("exact_dedup_hash", ""),
            "severity": f.get("severity", "INFO"),
            "category": f.get("category", ""),
            "is_chain": bool(f.get("is_chain", 0)),
            "dork_string": f.get("dork_string", ""),
            "cwe_id": f.get("cwe_id", ""),
            "cvss_vector": f.get("cvss_vector", ""),
            "cvss_score": float(f.get("cvss_score", 0.0)),
            "matched_endpoint": f.get("matched_endpoint", ""),
            "ast_node_type": f.get("ast_node_type", ""),
            "ast_context_snippet": f.get("ast_context_snippet", ""),
            "entropy_bits": float(f.get("entropy_bits", 0.0)),
            "confidence_pct": float(f.get("confidence_pct", 0.0)),
            "is_suppressed_fp": bool(f.get("is_suppressed_fp", 0)),
            "stealth_curl_poc": f.get("stealth_curl_poc", ""),
            "remediation": f.get("remediation", ""),
        }
        lines.append(json.dumps(rec, separators=(",", ":")))

    for ep in endpoints:
        lines.append(
            json.dumps(
                {
                    "record_type": "endpoint",
                    "scan_id": int(session.get("scan_id", 0)),
                    "endpoint_url": ep.get("endpoint_url", ""),
                    "source_type": ep.get("source_type", ""),
                    "http_status": int(ep.get("http_status", 0)),
                    "is_vendor_asset": bool(ep.get("is_vendor_asset", 0)),
                },
                separators=(",", ":"),
            )
        )

    return "\n".join(lines) + "\n"


def write_sarif_report(db_path: str, scan_id: int, out_path: str) -> Path:
    ctx = load_scan_report_context(db_path, scan_id)
    sarif_obj = render_sarif_report(ctx)
    dest = _assert_safe_output_dest(out_path)
    dest.write_text(json.dumps(sarif_obj, indent=2) + "\n", encoding="utf-8")
    return dest


def write_jsonl_report(db_path: str, scan_id: int, out_path: str) -> Path:
    ctx = load_scan_report_context(db_path, scan_id)
    jsonl_text = render_jsonl_report(ctx)
    dest = _assert_safe_output_dest(out_path)
    dest.write_text(jsonl_text, encoding="utf-8")
    return dest
