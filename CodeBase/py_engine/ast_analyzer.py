"""Deep structural AST verification for JavaScript, YAML, JSON, and HTML artifacts.

Collaborates with the Rust spider as Stage-2 syntactic verification using
esprima (JS AST), pyyaml (YAML tree), json, and lxml/BeautifulSoup4 (HTML DOM).
"""

from __future__ import annotations

import json
import math
import os
import sqlite3
from pathlib import Path
from typing import Any

import esprima
import yaml
from bs4 import BeautifulSoup


PLACEHOLDER_MARKERS = (
    "your_api_key",
    "your-api-key",
    "changeme",
    "placeholder",
    "example",
    "dummy",
    "test_key",
    "redacted",
    "sample",
    "xxxx",
    "aaaa",
)


def calculate_shannon_entropy(text: str) -> float:
    """Computes Shannon information entropy H(X) in bits per character."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((cnt / length) * math.log2(cnt / length) for cnt in freq.values())


def is_placeholder(val: str) -> bool:
    low = val.strip().lower()
    if len(low) < 6:
        return True
    return any(marker in low for marker in PLACEHOLDER_MARKERS)


def verify_html_dom_ast(html_text: str, check_kind: str) -> tuple[bool, str]:
    """Validates HTML DOM semantics without relying on raw substring scanning."""
    soup = BeautifulSoup(html_text, "lxml")
    title_el = soup.find("title")
    title_text = title_el.get_text(" ", strip=True) if title_el else ""

    if check_kind == "dir_index":
        has_title = "index of" in title_text.lower()
        anchors = soup.select("pre a[href], table a[href], ul li a[href]")
        has_listing = any(
            a.get("href", "") in ("../", "?C=N;O=D")
            or "parent directory" in a.get_text("", strip=True).lower()
            or "." in a.get("href", "")
            for a in anchors
        )
        return (has_title and has_listing), f"DOM_TITLE='{title_text}' anchors={len(anchors)}"

    if check_kind == "login_portal":
        has_pw = bool(soup.find("input", attrs={"type": "password"}))
        has_auth_form = any(
            any(
                tok in str(form.get(attr, "")).lower()
                for tok in ("login", "signin", "sign-in", "auth", "sso", "oauth", "saml")
            )
            for form in soup.find_all("form")
            for attr in ("action", "id", "name", "class")
        )
        return (has_pw or has_auth_form), f"password_input={has_pw} auth_form={has_auth_form}"

    return True, f"DOM_TITLE='{title_text}'"


def _walk_esprima_assignments(node: Any, out: list[tuple[str, str]]) -> None:
    """Recursively extracts (key, string_literal_value) from JS AST assignment/property nodes."""
    if node is None:
        return
    if isinstance(node, list):
        for item in node:
            _walk_esprima_assignments(item, out)
        return
    if not hasattr(node, "type"):
        return

    ntype = node.type
    if ntype == "VariableDeclarator":
        key_name = getattr(getattr(node, "id", None), "name", None)
        init = getattr(node, "init", None)
        if key_name and getattr(init, "type", None) == "Literal" and isinstance(init.value, str):
            out.append((str(key_name), init.value))
    elif ntype == "Property":
        key_node = getattr(node, "key", None)
        key_name = getattr(key_node, "name", None) or getattr(key_node, "value", None)
        val_node = getattr(node, "value", None)
        if key_name and getattr(val_node, "type", None) == "Literal" and isinstance(val_node.value, str):
            out.append((str(key_name), val_node.value))
    elif ntype == "AssignmentExpression":
        left = getattr(node, "left", None)
        right = getattr(node, "right", None)
        key_name = getattr(left, "name", None) or getattr(getattr(left, "property", None), "name", None)
        if key_name and getattr(right, "type", None) == "Literal" and isinstance(right.value, str):
            out.append((str(key_name), right.value))

    for attr_name in dir(node):
        if attr_name.startswith("_") or attr_name in ("type", "loc", "range"):
            continue
        child = getattr(node, attr_name, None)
        if isinstance(child, list) or hasattr(child, "type"):
            _walk_esprima_assignments(child, out)


def verify_js_ast_secret(js_source: str, target_keywords: tuple[str, ...] = ("aws", "secret", "key", "token", "password")) -> dict[str, Any]:
    """Parses JS with esprima (comment-aware) and checks structural secret assignments."""
    try:
        tree = esprima.parseScript(js_source, tolerant=True)
    except Exception:
        try:
            tree = esprima.parseModule(js_source, tolerant=True)
        except Exception as exc:
            return {"parsed": False, "error": str(exc), "verified_secrets": [], "suppressed_low_entropy": 0}

    assignments: list[tuple[str, str]] = []
    _walk_esprima_assignments(tree, assignments)

    verified_secrets: list[dict[str, Any]] = []
    suppressed_low_entropy = 0

    for key_name, val in assignments:
        key_low = key_name.lower()
        if any(kw in key_low for kw in target_keywords):
            ent = calculate_shannon_entropy(val)
            min_ent = 3.0 if val.startswith("AKIA") else 3.2
            if is_placeholder(val) or ent < min_ent:
                suppressed_low_entropy += 1
            else:
                redacted = f"{val[:4]}****{val[-4:]}" if len(val) > 8 else "****"
                verified_secrets.append(
                    {
                        "key": key_name,
                        "redacted": redacted,
                        "entropy_bps": round(ent * 100),
                    }
                )

    return {
        "parsed": True,
        "total_assignments": len(assignments),
        "verified_secrets": verified_secrets,
        "suppressed_low_entropy": suppressed_low_entropy,
    }


def verify_yaml_ast(yaml_text: str) -> tuple[bool, list[str]]:
    """Parses YAML syntax tree and checks valid structural configuration keys."""
    low = yaml_text.lstrip().lower()
    if low.startswith("<!doctype html") or low.startswith("<html"):
        return False, []
    try:
        loaded = yaml.safe_load(yaml_text)
    except yaml.YAMLError:
        return False, []
    if isinstance(loaded, dict):
        return True, [str(k) for k in loaded.keys()]
    if isinstance(loaded, list) and loaded:
        return True, [f"list[{len(loaded)}]"]
    return False, []


def verify_json_ast(json_text: str) -> tuple[bool, list[str]]:
    """Parses JSON document and checks valid object/array keys."""
    try:
        loaded = json.loads(json_text)
    except json.JSONDecodeError:
        return False, []
    if isinstance(loaded, dict):
        return True, [str(k) for k in loaded.keys()]
    if isinstance(loaded, list):
        return True, [f"array[{len(loaded)}]"]
    return False, []


def verify_scan_findings_in_db(db_path: str, scan_id: int, harvest_dir: str | None = None) -> dict[str, int]:
    """Performs Stage-2 Python AST confirmation on persisted findings for a scan.

    When harvest_dir is supplied, inspects harvested asset files using esprima/pyyaml/lxml.
    Any structural mismatch (e.g. non-YAML pretending to be YAML, or JS string literal without
    an assignment node) is flagged as suppressed FP inside an IMMEDIATE WAL transaction.
    """
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row

    harvested_texts: dict[str, str] = {}
    if harvest_dir:
        hpath = Path(harvest_dir)
        if hpath.is_dir() and not hpath.is_symlink():
            for entry in sorted(hpath.iterdir()):
                if entry.is_file() and not entry.is_symlink():
                    try:
                        harvested_texts[entry.name] = entry.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        pass

    cur = conn.cursor()
    rows = cur.execute(
        """
        SELECT df.finding_id, df.ast_node_type, df.matched_endpoint, df.shannon_entropy_bps,
               df.is_suppressed_fp, dc.category, dc.dork_string
        FROM dork_findings df
        JOIN dork_catalog dc ON df.dork_id = dc.dork_id
        WHERE df.scan_id = ?
        """,
        (scan_id,),
    ).fetchall()

    confirmed = 0
    ast_rejected = 0

    conn.execute("BEGIN IMMEDIATE;")
    try:
        for row in rows:
            if row["is_suppressed_fp"]:
                continue
            node_type = row["ast_node_type"]
            endpoint = row["matched_endpoint"].lower()
            rejected = False

            # Match against harvested artifacts if available
            if node_type.startswith("YAML_") and harvested_texts:
                yaml_candidates = [
                    txt for name, txt in harvested_texts.items() if name.endswith((".yaml", ".yml"))
                ]
                if yaml_candidates and not any(verify_yaml_ast(t)[0] for t in yaml_candidates):
                    rejected = True

            if node_type.startswith("JSON_") and harvested_texts:
                json_candidates = [
                    txt for name, txt in harvested_texts.items() if name.endswith(".json")
                ]
                if json_candidates and not any(verify_json_ast(t)[0] for t in json_candidates):
                    rejected = True

            if node_type == "JS_SECRET_ASSIGN" and harvested_texts:
                js_candidates = [
                    txt for name, txt in harvested_texts.items() if name.endswith(".js")
                ]
                if js_candidates:
                    any_verified = any(
                        bool(verify_js_ast_secret(t)["verified_secrets"]) for t in js_candidates
                    )
                    if not any_verified and "aws" in endpoint:
                        rejected = True

            if rejected:
                ast_rejected += 1
                conn.execute(
                    "UPDATE dork_findings SET is_suppressed_fp = 1, severity = 'INFO' WHERE finding_id = ?",
                    (row["finding_id"],),
                )
            else:
                confirmed += 1

        if ast_rejected > 0:
            conn.execute(
                "UPDATE scan_telemetry SET ast_fp_dropped = ast_fp_dropped + ? WHERE scan_id = ?",
                (ast_rejected, scan_id),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        conn.close()
        raise

    conn.close()
    return {"confirmed": confirmed, "ast_rejected": ast_rejected}
