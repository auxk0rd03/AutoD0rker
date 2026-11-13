"""CycloneDX 1.5, SPDX 2.3, and Markdown SBOM ledger generator for AutoDorker."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _sha256_file(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        return "UNAVAILABLE"
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_requirements(req_path: Path) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    if not req_path.is_file():
        return items
    for line in req_path.read_text(encoding="utf-8").splitlines():
        clean = line.strip()
        if not clean or clean.startswith("#"):
            continue
        if "==" in clean:
            name, ver = clean.split("==", 1)
            items.append({"name": name.strip(), "version": ver.strip(), "ecosystem": "pypi"})
        else:
            items.append({"name": clean, "version": "unspecified", "ecosystem": "pypi"})
    return items


def _parse_cargo_direct_deps(cargo_toml: Path, cargo_lock: Path) -> list[dict[str, str]]:
    if not cargo_toml.is_file():
        return []
    toml_data = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
    direct_names = set(toml_data.get("dependencies", {}).keys())

    locked_versions: dict[str, str] = {}
    if cargo_lock.is_file():
        current_name = None
        for line in cargo_lock.read_text(encoding="utf-8").splitlines():
            m_name = re.match(r'^name\s*=\s*"([^"]+)"', line.strip())
            if m_name:
                current_name = m_name.group(1)
                continue
            m_ver = re.match(r'^version\s*=\s*"([^"]+)"', line.strip())
            if m_ver and current_name:
                locked_versions[current_name] = m_ver.group(1)
                current_name = None

    deps = []
    for name in sorted(direct_names):
        deps.append({
            "name": name,
            "version": locked_versions.get(name, "locked"),
            "ecosystem": "cargo",
        })
    return deps


def generate_sbom_manifests(codebase_dir: Path) -> dict[str, Path]:
    """Generates SBOM.cyclonedx.json, SBOM.spdx.json, and SBOM.md inside codebase_dir."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    py_deps = _parse_requirements(codebase_dir / "requirements.txt")
    rust_deps = _parse_cargo_direct_deps(
        codebase_dir / "crates" / "dork_spider" / "Cargo.toml",
        codebase_dir / "crates" / "dork_spider" / "Cargo.lock",
    )

    vendored_assets = [
        ("htmx.min.js", "2.0.4", codebase_dir / "web" / "static" / "js" / "htmx.min.js"),
        ("JetBrainsMono.woff2", "2.304", codebase_dir / "web" / "static" / "fonts" / "JetBrainsMono.woff2"),
        ("synth-ledger.css", "1.0.0", codebase_dir / "web" / "static" / "css" / "synth-ledger.css"),
        ("autodorker-ui.js", "1.0.0", codebase_dir / "web" / "static" / "js" / "autodorker-ui.js"),
        ("DorkSet.csv", "295-rules", codebase_dir.parent / "Docs" / "DorkSet.csv"),
    ]

    components_cdx: list[dict[str, Any]] = []
    packages_spdx: list[dict[str, Any]] = []

    for dep in py_deps + rust_deps:
        purl = f"pkg:{dep['ecosystem']}/{dep['name']}@{dep['version']}"
        components_cdx.append({
            "type": "library",
            "bom-ref": purl,
            "name": dep["name"],
            "version": dep["version"],
            "purl": purl,
        })
        packages_spdx.append({
            "SPDXID": f"SPDXRef-{dep['ecosystem']}-{re.sub(r'[^A-Za-z0-9.-]', '-', dep['name'])}",
            "name": dep["name"],
            "versionInfo": dep["version"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
        })

    asset_hashes: list[tuple[str, str, str]] = []
    for name, ver, fpath in vendored_assets:
        digest = _sha256_file(fpath)
        asset_hashes.append((name, ver, digest))
        components_cdx.append({
            "type": "file",
            "bom-ref": f"asset:{name}",
            "name": name,
            "version": ver,
            "hashes": [{"alg": "SHA-256", "content": digest}],
        })
        packages_spdx.append({
            "SPDXID": f"SPDXRef-asset-{re.sub(r'[^A-Za-z0-9.-]', '-', name)}",
            "name": name,
            "versionInfo": ver,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
        })

    cdx_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now_iso,
            "component": {
                "type": "application",
                "name": "AutoDorker",
                "version": "1.0.0",
                "supplier": {"name": "CyberNest Holdings LLC - Labs Department"},
            },
        },
        "components": components_cdx,
    }

    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "AutoDorker-1.0.0-SBOM",
        "documentNamespace": "https://cybernest.local/spdx/autodorker-1.0.0",
        "creationInfo": {
            "created": now_iso,
            "creators": ["Tool: AutoDorker-SBOM-Generator-1.0"],
        },
        "packages": packages_spdx,
    }

    md_lines = [
        "# AutoDorker Software Bill of Materials (SBOM)",
        "",
        f"- **Generated (UTC)**: `{now_iso}`",
        "- **Project**: `AutoDorker v1.0.0` (CyberNest Holdings LLC - Labs Department)",
        "- **Go Gateway (`cmd/gateway/`)**: Standard Library Only (zero third-party Go modules; `GOFIPS=1` / `GOFIPS140=v1.0.0`)",
        "",
        "## Python Dependencies (`requirements.txt`)",
        "",
        "| Package | Version |",
        "| :--- | :--- |",
    ]
    for d in py_deps:
        md_lines.append(f"| `{d['name']}` | `{d['version']}` |")

    md_lines.extend([
        "",
        "## Rust Direct Dependencies (`crates/dork_spider/Cargo.toml`)",
        "",
        "| Crate | Locked Version |",
        "| :--- | :--- |",
    ])
    for d in rust_deps:
        md_lines.append(f"| `{d['name']}` | `{d['version']}` |")

    md_lines.extend([
        "",
        "## Vendored Assets & Rulebook SHA-256 Ledger",
        "",
        "| Artifact | Version | SHA-256 |",
        "| :--- | :--- | :--- |",
    ])
    for name, ver, digest in asset_hashes:
        md_lines.append(f"| `{name}` | `{ver}` | `{digest}` |")
    md_lines.append("")

    cdx_path = codebase_dir / "SBOM.cyclonedx.json"
    spdx_path = codebase_dir / "SBOM.spdx.json"
    md_path = codebase_dir / "SBOM.md"

    cdx_path.write_text(json.dumps(cdx_doc, indent=2) + "\n", encoding="utf-8")
    spdx_path.write_text(json.dumps(spdx_doc, indent=2) + "\n", encoding="utf-8")
    md_path.write_text("\n".join(md_lines), encoding="utf-8")

    return {"cyclonedx": cdx_path, "spdx": spdx_path, "markdown": md_path}
