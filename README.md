# AutoDorker — CyberNest Labs Autonomous Dork & AST Surface Verification Engine

**AutoDorker** is a local-first, air-gapped-capable RPGS (**Rust, Python, Go, POSIX Shell**) + **SQLite3 (WAL)** + **HTMX 2.0** security auditing utility developed by **CyberNest Labs** (CyberNest Holdings LLC). It audits single or multi-target URLs (`url1,url2,url3,...` or `.csv` lists) against the curated 295-rule `Docs/DorkSet.csv` catalog without sending reconnaissance telemetry to third-party search engines.

---

## Core Architecture (`SYS.01 NOCTURNAL SYNTH-LEDGER`)

- **`[G]` Go Loopback Gateway (`CodeBase/cmd/gateway/`)**: Zero-dependency Go 1.24+ server compiled with `GOFIPS=1` (`GOFIPS140=v1.0.0`). Binds strictly to `127.0.0.1:8090` (scanning `8000–8100` if occupied), enforces strict local CSP (`script-src 'self'`, zero external CDNs), validates `url1,url2,url3` / `.csv` inputs with an SSRF firewall, and multiplexes Rust, Python, and POSIX shell subprocesses over scrubbed environments.
- **`[R]` Rust Dork Spider, AST Compiler & Entropy Engine (`CodeBase/crates/dork_spider/`)**: Compiles all 295 `DorkSet.csv` rules (32 `[CHAIN]` + 263 atomic) into Boolean Dork Query ASTs, executes bounded BFS crawling (`MAX_HTML_PAGES = 25`, `MAX_JS_FILES = 50`, Webpack/Vite/Rollup chunk resolution), evaluates Gate 1 DOM/JS/Config AST rules + Gate 2 Shannon Entropy ($H(X)$) + 64-bit DOM SimHash Soft-404 suppression, and emits `hx-swap-oob="true"` HTMX fragments.
- **`[P]` Python AST & Document Generation Engine (`CodeBase/py_engine/`)**: Runs Stage-2 structural AST confirmation (`esprima`, `pyyaml`, `lxml`, `beautifulsoup4`), renders flat orthogonal `<svg>` telemetry charts, generates CycloneDX 1.5 / SPDX 2.3 / Markdown SBOMs, and exports CyberNest VIDS Bug Bounty Markdown (`.md`) and Enterprise Microsoft Word (`.docx`) reports with Chrome 124 Stealth `curl` PoCs.
- **`[S]` POSIX Shell Lifecycle & Backup Daemons (`CodeBase/scripts/`, `CodeBase/dev.sh`, `CodeBase/dev.bat`)**: Implements `CN-DIR-2026-004` Linux/Windows command parity (`setup`, `build`, `run`, `cli`, `simulate`, `test`, `fmt`), `CWE-114` PID locking, `CWE-377` symlink hardening, 30-second WAL telemetry polling, and atomic SQLite `VACUUM INTO` hot backups signed with SHA-256.

---

## Quick Start

```bash
cd CodeBase

# 1. Verify toolchain & provision Python .venv
./dev.sh setup          # Windows: dev.bat setup

# 2. Build Rust + Go binaries, seed DorkSet.csv (295 rules), and generate SBOMs
./dev.sh build          # Windows: dev.bat build

# 3. Run Rust, Go, and Python E2E verification suites
./dev.sh test           # Windows: dev.bat test

# 4. Run ephemeral mock HTTP simulation
./dev.sh simulate       # Windows: dev.bat simulate

# 5. Launch loopback web dashboard (http://127.0.0.1:8090)
./dev.sh run            # Windows: dev.bat run
```

---

## Documentation & Licensing

- **Developer Handoff Manual**: See [Handoff.md](Handoff.md) for the complete file-by-file breakdown, architecture walkthrough, implemented capabilities, modification guide, and prioritized roadmap.
- **Engineering Design Document**: See [Docs/AutoDorkerDevDoc.md](Docs/AutoDorkerDevDoc.md).
- **License**: Authorized defensive research & dual-use terms in [LICENSE](LICENSE) and [Docs/LICENSE](Docs/LICENSE).
