# AutoDorker — Enterprise Handoff & Engineering Reference Manual

**Document Classification:** Internal Engineering Handoff // Defensive Security Tooling  
**Organization:** CyberNest Holdings LLC — CyberNest Labs Department  
**Compliance Baselines:** `CN-LABS-H2C-2026-01`, `CN-LABS-BRW-2026-02`, `CN-DIR-2026-004`, CMMC 2.0 Level 2  
**Architecture Stack:** **RPGS** (**R**ust + **P**ython + **G**o + POSIX **S**hell) + **SQLite3 (WAL Mode)** + **HTMX 2.0** (`SYS.01 NOCTURNAL SYNTH-LEDGER`, v2.0)  

---

## 1. Executive Summary & Architectural Design

**AutoDorker** is a local-first autonomous web-surface auditing and dork verification platform engineered from [Docs/AutoDorkerDevDoc.md](Docs/AutoDorkerDevDoc.md). While its web UI and gateway strictly enforce **loopback GUI binding (`127.0.0.1:8090`)**, outbound scans traverse the **public internet** through a DNS-pinned, SSRF-hardened fetcher (`PinnedSsrfResolver`) with optional corporate `HTTP_PROXY`/`HTTPS_PROXY` support and loopback staging toggles.

Instead of forwarding target reconnaissance telemetry to external search engines, AutoDorker compiles all **295 signatures** in [Docs/DorkSet.csv](Docs/DorkSet.csv) (**32 `[CHAIN]` rules** and **263 atomic rules**) into a typed **Boolean Dork Abstract Syntax Tree (AST)** and executes deterministic local verification directly against harvested HTTP, DOM, JavaScript, JSON, YAML, SQL, and configuration assets.

### Polyglot Responsibility Matrix (RPGS)

1. **`[R]` Rust Execution Engine (`CodeBase/crates/dork_spider/`)**
   - Compiles Google Dork syntax (including real-world GHDB quirks) into `DorkExpr` ASTs and synthesizes safe active probe paths (`inurl:`, `ext:`, `filetype:`, quoted phrases, plus optional custom wordlists and category filters).
   - Executes a bounded breadth-first spider (`MAX_HTML_PAGES = 25`, `MAX_JS_FILES = 50`, `MAX_CONFIG_FILES = 50`, `MAX_ACTIVE_PROBES = 45`) with **6-pillar L7 stealth impersonation** (Chrome 124 headers, configurable jitter range, WAF detection & circuit breaker, Soft-404 baseline fingerprinting).
   - Enforces **DNS pinning directly inside `ureq::Resolver`** (`PinnedSsrfResolver`, IPv4-first ordering, canonical `www.<apex> <-> <apex>` redirect promotion, query-stripped asset classification, static `.css`/font/media skip, `/robots.txt` passive harvest, Stage-0 `--spa-seed` ingestion, and explicit upstream proxy validation).
   - Evaluates **Stage-1 Gate 0/1/2 + Cross-Asset `[CHAIN]` Correlation** (64-bit DOM Tag SimHash Soft-404 suppression, structural DOM/JS/Config checks, Shannon entropy `H(X)` in integer basis points, and cross-asset attack-chain correlation across `.git`, `robots.txt`, OpenAPI/Swagger, login portals, directory listings, and high-entropy secrets).
   - Persists sessions, telemetry, endpoints, and verified findings into **SQLite3 WAL**, exposes history/categories/compare JSON CLI modes (`--history-json`, `--categories-json`, `--compare-scans`), and emits HTML-escaped HTMX `hx-swap-oob="true"` table/KPI fragments.

2. **`[P]` Python AST, SPA & Deliverable Engine (`CodeBase/py_engine/`)**
   - Performs **Stage-2 deep syntactic verification** using `esprima` (ECMAScript AST walker), `pyyaml` (`SafeLoader`), `lxml`, and `BeautifulSoup4`.
   - Provides optional **Stage-0 Headless Browser SPA DOM Hydration** (`spa_hydrator.py`, Playwright / headless Chromium `--dump-dom` routed strictly through the Go SSRF forward proxy, degrading cleanly when absent).
   - Renders server-side orthogonal flat `<svg>` visual telemetry (`SYS.01` palette, zero rounded corners).
   - Generates **CyberNest VIDS Bug Bounty Markdown (`.md`)**, **Enterprise Microsoft Word (`.docx`)**, **SARIF v2.1.0 (`.sarif`)**, and **JSON-Lines / NDJSON (`.jsonl`)** deliverables complete with CVSS v3.1 metadata, redacted AST snippets, chained impact analysis, and copy-paste **Chrome 124 Stealth `curl` PoCs**.
   - Provides cross-platform Windows/POSIX telemetry & signed `VACUUM INTO` DB backups (`sys_ops.py`) and auto-generates CycloneDX 1.5 (`SBOM.cyclonedx.json`), SPDX 2.3 (`SBOM.spdx.json`), and Markdown (`SBOM.md`) manifests on build.

3. **`[G]` Go Loopback Gateway, Batch Orchestrator & SSRF Firewall (`CodeBase/cmd/gateway/`)**
   - Zero-external-dependency Go 1.24+ HTTP server compiled with `//go:debug fips140=on` (`GOFIPS=1 GOFIPS140=v1.0.0`).
   - Enforces **strict loopback GUI binding (`127.0.0.1:8090`**, scanning `8000–8100` if busy), strict local Content Security Policy (`script-src 'self'`, zero external CDNs), and **SSRF defense** (`secguard`, including IPv6 literal normalization, `ValidateOutboundProxy`, `SanitizeWordlistInput`, `SanitizeCategoriesInput`, RFC 1918, loopback, CGNAT `100.64.0.0/10`, link-local, IPv6 ULA `fc00::/7`, and unconditional cloud metadata `169.254.169.254`).
   - Runs a bounded concurrent batch worker queue (`BatchManager` with `context.WithCancel`, `/api/scan/{batch_id}/cancel`, `batchProgress` SSE bar), an ephemeral **loopback SSRF-filtering HTTP/CONNECT proxy** (`spa_proxy.go`) for Stage-0 SPA hydration, preserves proxy & CA trust env vars safely for internet scans in `scrubbedEnv()`, clears SSE response write deadlines so live telemetry streams never drop at 90s, and supports **embedded UI (`embed.FS`, `--embedded-ui`) + release packaging (`archive/tar`, `--package-release`)**.

4. **`[S]` POSIX Shell & Windows Parity (`CodeBase/dev.sh`, `dev.bat`, `scripts/`)**
   - Implements unified `CN-DIR-2026-004` commands (`setup`, `build`, `run`, `serve`, `cli`, `simulate`, `test`, `package`, `fmt`).
   - Enforces `CWE-377` symlink refusal + `0700`/`0600` file permissions and `CWE-114` PID locking.
   - Polls live SQLite3 WAL health (`scripts/sys_telemetry.sh` + `py_engine/sys_ops.py`) and executes atomic `VACUUM INTO` backups signed with truncated SHA-256 audit hashes (`scripts/backup_and_sign.sh` + `py_engine/sys_ops.py`).

---

## 2. Repository Layout & File Tree

The Git repository root sits at `AutoDorker/` so `CodeBase/` reliably resolves `../Docs/DorkSet.csv` and repository-wide documentation stays synchronized.

```text
AutoDorker/
├── .gitignore
├── Handoff.md                               # This engineering manual
├── LICENSE                                  # Root CyberNest Dual-Use Research License (AutoDorker)
├── README.md                                # Quickstart and architecture summary
├── Docs/
│   ├── AutoDorkerDevDoc.md                  # Master Engineering Design Document (EDD)
│   ├── AutoDorkerOutline.md                 # High-level project outline
│   ├── BlackRouteWebHandoff.md              # Reference handoff & stealth baseline
│   ├── DorkSet.csv                          # Curated 295-signature Google Dork catalog
│   ├── How2Code_CyberNestLabsRustGoR&DGuide.md
│   └── LICENSE                              # Docs mirror of AutoDorker LICENSE
└── CodeBase/
    ├── Makefile                             # Delegates build/test/run targets to ./dev.sh
    ├── SBOM.cyclonedx.json                  # CycloneDX 1.5 bill of materials
    ├── SBOM.md                              # Markdown SBOM & cryptographic inventory
    ├── SBOM.spdx.json                       # SPDX 2.3 bill of materials
    ├── dev.bat                              # Windows 10/11 CLI parity orchestrator (incl. package/telemetry)
    ├── dev.sh                               # POSIX / Linux CLI orchestrator (CN-DIR-2026-004)
    ├── go.mod                               # Root Go module enabling embed.FS over web/ (zero Go deps)
    ├── launcher.bat                         # Interactive Windows menu wrapper
    ├── launcher.sh                          # Interactive POSIX menu wrapper
    ├── requirements.txt                     # Pinned Python 3 AST, DOM & DOCX dependencies
    ├── webassets.go                         # //go:embed all:web bundle for standalone --embedded-ui
    ├── bin/
    │   └── .gitkeep                         # Staging folder for compiled dork_spider & gateway
    ├── cmd/
    │   └── gateway/
    │       ├── exec_bridge.go               # Scrubbed env, BatchManager queue, Stage-0/1/2 orchestration
    │       ├── main.go                      # Loopback listener, --embedded-ui, --package-release, FIPS-140
    │       ├── packager.go                  # stdlib archive/tar + gzip self-contained release bundler
    │       ├── routes.go                    # HTTP/HTMX routes, SSE hub, history/diff, SARIF/JSONL/ZIP
    │       ├── security.go                  # Package-local wrappers delegating to secguard
    │       ├── security_test.go             # Gateway unit tests for loopback, SSRF, and SPA proxy
    │       ├── spa_proxy.go                 # Loopback HTTP/CONNECT SSRF proxy for Stage-0 Chromium
    │       └── secguard/
    │           ├── secguard.go              # SSRF IP filter, IPv6/proxy/wordlist/category & path guards
    │           └── secguard_test.go         # Dedicated unit tests covering all secguard validators
    ├── crates/
    │   └── dork_spider/
    │       ├── Cargo.lock                   # Reproducible Rust crate dependency lockfile
    │       ├── Cargo.toml                   # Rust 2024 crate manifest (LTO release profile)
    │       └── src/
    │           ├── ast_verifier.rs          # Gate 0/1/2 + Cross-Asset [CHAIN] Correlator
    │           ├── db.rs                    # SQLite3 WAL persistence, risk scoring, cURL PoC builder
    │           ├── dork_ast.rs              # Lexer, recursive-descent Dork AST compiler & safe probe synth
    │           ├── entropy.rs               # Shannon H(X), 64-bit DOM Tag SimHash, redaction & placeholders
    │           ├── html.rs                  # CSP-clean HTMX table rows (.MD/.DOCX/.SARIF/.JSONL) & OOB KPIs
    │           ├── lib.rs                   # Crate module exports
    │           ├── main.rs                  # Rust CLI (--ingest-csv, --scan, --render, --history/compare)
    │           └── spider.rs                # DNS-pinned PinnedSsrfResolver, BFS crawler, proxy & SPA seed
    ├── data/
    │   ├── Output/
    │   │   └── .gitkeep                     # Per-target deliverables Output/TargXXX/
    │   ├── backups/
    │   │   └── .gitkeep                     # Atomic VACUUM INTO WAL snapshots
    │   └── migrations/
    │       └── 001_init_schema.sql          # SQLite3 WAL pragmas, 5 normalized tables & 4 indexes
    ├── py_engine/
    │   ├── __init__.py
    │   ├── ast_analyzer.py                  # Stage-2 esprima/pyyaml/lxml AST confirmation engine
    │   ├── cli.py                           # Python CLI (--verify-ast, --svg, --export-*, --hydrate-spa, etc.)
    │   ├── report_docx.py                   # Pure OpenXML Enterprise Word (.docx) generator
    │   ├── report_md.py                     # CyberNest VIDS Bug Bounty Markdown (.md) generator
    │   ├── report_structured.py             # SARIF v2.1.0 & JSON-Lines (.jsonl) exporters
    │   ├── sbom_gen.py                      # Deterministic CycloneDX/SPDX/Markdown SBOM builder
    │   ├── spa_hydrator.py                  # Optional Playwright / Chromium Stage-0 SPA DOM hydrator
    │   ├── svg_telemetry.py                 # Server-side orthogonal SYS.01 <svg> bar chart emitter
    │   └── sys_ops.py                       # Cross-platform telemetry badge & VACUUM INTO backup signer
    ├── scripts/
    │   ├── backup_and_sign.sh               # POSIX VACUUM INTO snapshot + SHA-256 audit badge
    │   └── sys_telemetry.sh                 # POSIX top-bar WAL & GUI:127.0.0.1 / EGRESS:INTERNET telemetry
    ├── tests/
    │   ├── go.mod                           # Standalone Go test module linked to parent CodeBase module
    │   ├── ssrf_runner_test.go              # Test runners invoking test_security_ssrf.go checks
    │   ├── test_dork_ast.rs                 # Rust tests (295 rules, [CHAIN] correlator, DNS pin, 5.5k fuzz)
    │   ├── test_exports_e2e.py              # Full-stack E2E (AST, SPA, SARIF/JSONL/MD/DOCX/ZIP, history, pkg)
    │   └── test_security_ssrf.go            # Multi-URL/CSV, injection, SSRF & symlink traversal guards
    └── web/
        ├── static/
        │   ├── css/
        │   │   └── synth-ledger.css         # SYS.01 NOCTURNAL SYNTH-LEDGER stylesheet (0px radius)
        │   ├── fonts/
        │   │   └── JetBrainsMono.woff2      # Vendored local monospace font (v2.304)
        │   └── js/
        │       ├── autodorker-ui.js         # SSE EventSource, progress/cancel, history/diff, CSP-safe events
        │       └── htmx.min.js              # Vendored local HTMX v2.0.4 (zero external CDNs)
        └── templates/
            ├── index.html                   # Single-page dashboard (GUI/egress status, progress, history/diff)
            └── partials/
                ├── input_batch.html         # HTMX partial: Multi-URL / .CSV upload mode
                ├── input_single.html        # HTMX partial: Single URL scan mode
                └── scan_options.html        # Shared advanced controls (depth, jitter, proxy, wordlist, SPA)
```

**Note on Excluded Artifacts:** `.gitignore` strictly excludes `.venv/`, `CodeBase/bin/dork_spider`, `CodeBase/bin/gateway`, `CodeBase/crates/dork_spider/target/`, SQLite runtime files (`*.db`, `*.db-wal`, `*.db-shm`, `*.db-journal`), `CodeBase/data/backups/*`, `CodeBase/data/Output/*`, runtime `.pid`/`.log` files, temporary `adk_harvest_*` directories, and credential extensions (`.env`, `.pem`, `.key`, `.jks`).

---

## 3. End-to-End Runtime Data Flow

```mermaid
flowchart LR
    UI["SYS.01 Web UI (127.0.0.1 // HTMX 2.0 + SSE)"] -->|"POST /api/scan (+options)"| GW["Go Gateway (127.0.0.1:8090 // FIPS-140)"]
    GW -->|"secguard.ParseTargetInputWithOptions + ValidateOutboundProxy"| VAL{"SSRF & Injection Guard"}
    VAL -->|"Rejected (400)"| UI
    VAL -->|"BatchManager Queue + adk_harvest_*"| SPA{"Optional Stage-0 SPA?"}
    SPA -->|"Yes: via 127.0.0.1 SSRF Proxy"| HYD["py_engine spa_hydrator.py -> spa_seed.json"]
    SPA -->|"Skip / Fallback"| RS
    HYD --> RS["Rust dork_spider (PinnedSsrfResolver // IPv4-first Internet Egress)"]
    RS -->|"HTTPS over Internet / Staging"| TGT["Authorized Target(s)"]
    TGT -->|"robots.txt + HTTP/HTML/JS/Config + Canonical Redirects"| RS
    RS -->|"Gate 0/1/2 AST + Shannon H(X) + [CHAIN] Correlator"| DB[("SQLite3 WAL DB")]
    RS -->|"Live stderr stream ([NET]/[AST])"| SSE["SSEHub -> /api/stream-logs-sse"]
    SSE --> UI
    GW -->|"Stage-2 Check"| PY1["Python ast_analyzer.py (--verify-ast)"]
    PY1 -->|"esprima / pyyaml / lxml updates"| DB
    GW -->|"os.RemoveAll(harvestDir)"| ZF["Zero-Footprint Purge"]
    GW -->|"Generate Deliverables"| PY2["Python report_md/docx/structured (--export-all)"]
    PY2 -->|"Output/TargXXX/*.md .docx .sarif .jsonl"| DB
    GW -->|"VACUUM INTO + SHA256"| SH["backup_and_sign.sh / sys_ops.py"]
    GW -->|"batchProgress / scanUpdated / scanCompleted"| UI
```

---

## 4. Detailed File-by-File Walkthrough & Modification Guide

### 4.1 Root & Documentation Files

| File | Purpose | How to Modify Safely |
| :--- | :--- | :--- |
| [`.gitignore`](.gitignore) | Prevents leaking `.venv/`, compiled binaries, runtime `.db` WAL files, backups, target outputs, logs, PID files, and secrets to Git. | Add new temp harvest prefixes or artifact extensions before running `git add`. Never remove `*.db*` or `.venv/`. |
| [`LICENSE`](LICENSE) & [`Docs/LICENSE`](Docs/LICENSE) | Authorized defensive research & dual-use license owned by CyberNest Holdings LLC (Author: Auxk0rd) governing AutoDorker (`DorkSet.csv`, `dork_spider`, `gateway`, `py_engine`, UI). | Keep both copies synchronized when bumping copyright years or terms. `Cargo.toml` references `LicenseRef-CyberNest-Dual-Use`. |
| [`README.md`](README.md) | Concise operator entrypoint covering stack overview and `./dev.sh` quickstart commands. | Update quickstart flags if `dev.sh` subcommands change; keep doc links relative. |
| [`Docs/DorkSet.csv`](Docs/DorkSet.csv) | Master CSV catalog (`Category,Dork Query,Description`) containing 295 dork rules (`32` `[CHAIN]`, `263` atomic). | Append CSV rows adhering to RFC-4180 quoting, then run `./bin/dork_spider --ingest-csv ../Docs/DorkSet.csv` or `./dev.sh build`. Update expected rule count in `tests/test_dork_ast.rs` if total rules change. |

---

### 4.2 Build, Orchestration & Shell Scripts (`CodeBase/`)

#### `CodeBase/dev.sh` (201 lines) & `CodeBase/launcher.sh` (34 lines)
- **What it does:** Implements `CN-DIR-2026-004` subcommands: `setup`, `build`, `run`/`serve`, `cli [url]`, `simulate`, `test`, `package [out.tar.gz]`, `fmt`. Guards against unnecessary `sudo` execution (`SUDO_USER` check halting with unprivileged usage hint so `~/.cargo` isn't hidden and root-owned artifacts aren't created), prepends `/usr/local/go/bin` and `${CARGO_HOME:-$HOME/.cargo}/bin` to `PATH`, enforces `require_tools()` preflight checks, and locks `Cargo.lock` builds (`cargo build --release --locked`). `init_secure_runtime_dir()` blocks symlinks (`[ -L ... ]` for `CWE-377`), enforces `0700` on `~/.cache/autodorker`, `umask 0077`, and PID locking (`gateway.pid` for `CWE-114`). `cmd_build()` builds Release Rust (`cargo build --release --locked`), builds FIPS-140 Go (`GOFIPS=1 GOFIPS140=v1.0.0 go build -ldflags="-s -w"`), ingests `DorkSet.csv`, and regenerates SBOMs.
- **How to modify:** Edit `BIND_ADDR`, `DB_PATH`, or `DORK_CSV` default fallbacks near lines 17–19 (overridable via `AUTODORKER_BIND_ADDR`, `AUTODORKER_DB_PATH`, `AUTODORKER_DORKSET_PATH`). Mirror any new subcommands in both `dev.bat` and `launcher.sh`/`launcher.bat`.

#### `CodeBase/dev.bat` (138 lines), `CodeBase/launcher.bat` (25 lines) & `CodeBase/Makefile` (28 lines)
- **What they do:** `dev.bat` and `launcher.bat` provide Windows 10/11 command parity using `%LOCALAPPDATA%\autodorker` and `.venv\Scripts\`, including `cmd_package` (`bin\gateway.exe --package-release`) and pure-Python `--telemetry-status` / `--backup-sign` execution in `cmd_cli`. `Makefile` exposes `make setup|build|run|serve|cli|simulate|test|fmt|clean` delegating directly to `./dev.sh`.
- **How to modify:** Keep `dev.bat` subcommand labels aligned 1:1 with `dev.sh`.

#### `CodeBase/scripts/sys_telemetry.sh` (36 lines)
- **What it does:** Emits the compact `SYS.01` top-bar HTML telemetry badge (`[DB: WAL_OK // ... KB] [DORKS: 295_ACTIVE // 32_CHAIN] [SYNC: HH:MM:SS UTC] [GUI: 127.0.0.1] [EGRESS: INTERNET]`). Refuses symlinked DB files (`CWE-377`). Uses `sqlite3` CLI when present or falls back to `.venv/bin/python`.
- **How to modify:** Keep output synchronized with `py_engine/sys_ops.py` and strictly bounded to inline HTML `<span class="val-...">` badges with zero `<script>` tags.

#### `CodeBase/scripts/backup_and_sign.sh` (45 lines)
- **What it does:** Validates non-symlink DB and backup paths (`CWE-377`), enforces `0700` directory and `0600` file modes, executes atomic `VACUUM INTO 'data/backups/autodorker_snapshot_<UTC>.db'`, computes the first 12 hex characters of SHA-256, and emits `[AUDIT_LOCK: YYYYMMDD_HHMMSS // SHA256:<prefix>]`.
- **How to modify:** Keep output format synchronized with `py_engine/sys_ops.py`.

---

### 4.3 Database Migration Schema (`CodeBase/data/migrations/`)

#### `CodeBase/data/migrations/001_init_schema.sql` (98 lines)
- **What it does:** Initializes SQLite3 WAL performance pragmas (`journal_mode = WAL`, `synchronous = NORMAL`, `temp_store = MEMORY`, `mmap_size = 268435456`, `cache_size = -64000`, `foreign_keys = ON`) and five tables (`dork_catalog`, `scan_sessions`, `dork_findings`, `scan_telemetry`, `harvested_endpoints`), storing CVSS, Shannon entropy, and confidence in integer basis points (`_bps`).
- **How to modify:** Add sequential `002_*.sql` migrations or extend `001_init_schema.sql` while keeping `crates/dork_spider/src/db.rs` and Python queries in `py_engine/` synchronized.

---

### 4.4 Rust Execution Engine (`CodeBase/crates/dork_spider/`)

- `Cargo.toml` (37 lines) & `src/lib.rs` (6 lines): Configures Rust 2024 edition crate `dork_spider`, release LTO (`opt-level = 3`, `lto = true`, `strip = true`), bundled SQLite (`rusqlite = 0.32`), `ureq = 2.10` (TLS+gzip), `scraper = 0.21`, `regex`, `csv`, `sha2`, `serde`, `rand`, `chrono`, `url`.

#### `src/dork_ast.rs` (708 lines)
- **What it does:** Lexes and parses arbitrary Google Dork syntax into `DorkExpr` (`Term(DorkOperator)`, `Not`, `And`, `Or`) using recursive descent. `synthesize_probe_paths(expr)` extracts actionable path/file probes while blocking whitespace, `*`, `?`, `:`, `..`, `\`, and control characters (`\0`, `\r`, `\n`). `classify_dork_rule()` assigns severity and `CWE-*` IDs across all 13 `DorkSet.csv` categories.
- **How to modify:** Extend `is_operator_name()`, `DorkOperator`, `synthesize_probe_paths()`, and `ast_verifier.rs` together; re-run `cargo test --locked`.

#### `src/entropy.rs` (231 lines)
- **What it does:** Computes Shannon entropy $H(X)$ in integer basis points (`shannon_entropy_bps`), 64-bit structural DOM SimHash (`dom_tag_simhash`), redacts exposed keys (`redact_secret`), and drops low-entropy placeholders (`AKIAXXXXXXXXXXXXXXXX`, `YOUR_API_KEY_HERE`, `changeme123`) below `300`/`320` bps.
- **How to modify:** Tune placeholder patterns or token regexes in `evaluate_secret_candidates()`; build test fixtures dynamically (`concat!`) to avoid secret-scanning false positives.

#### `src/ast_verifier.rs` (1,204 lines)
- **What it does:** Implements Dual-Gate verification PLUS the **Cross-Asset & Cross-Finding `[CHAIN]` Correlator (`correlate_chain_findings`)**:
  - `build_harvested_doc()` extracts `robots_disallowed` directives, `is_git_exposed`, `is_swagger_exposed`, HTML DOM login/dir-index markers, comment-stripped JS AST assignments, JSON/YAML structure, and CDN vendor status.
  - **Gate 0 / Gate 1 / Gate 2:** Drops soft-404 clones (`sim > 9200`), validates AST structures (`DOM_DIR_INDEX`, `DOM_LOGIN_FORM`, `JS_OBJ_PROP`, `YAML_KEY`, `JSON_KEY`, etc.), and enforces Shannon entropy thresholds (`--shadow` downgrades low-entropy hits instead of dropping).
  - **`correlate_chain_findings()`:** Filters through Gate 0 first-party non-error assets and correlates (1) multi-document `DorkExpr::And` branches (`CHAIN_MULTI_ASSET_RULE`), (2) `.git` exposure paired with `robots.txt` disallowed routes / Swagger / login / dir-index (`CHAIN_GIT_RECON_PIVOT`, `CRITICAL`), (3) `robots.txt` disallowed paths matching live accessible routes or OpenAPI/login (`CHAIN_ROBOTS_SURFACE_PIVOT`), and (4) dir-index / OpenAPI paired with verified high-entropy secrets (`CHAIN_SURFACE_SECRET_PIVOT`, `CRITICAL`), always anchoring to a real `dork_catalog(dork_id)` foreign key.
- **How to modify:** Adjust correlation rules cleanly inside `correlate_chain_findings()` and add synthetic scenarios in `tests/test_dork_ast.rs`.

#### `src/spider.rs` (1,293 lines)
- **What it does:** Executes bounded, DNS-pinned internet or staging crawls:
  - **DNS Pinning (`PinnedSsrfResolver` implementing `ureq::Resolver`):** Resolves once, validates every returned IP against `is_blocked_ip()` (IPv4 private/loopback/CGNAT `100.64.0.0/10`/link-local, IPv4-mapped IPv6 `::ffff:*`, IPv6 ULA `fc00::/7`/link-local, unconditional `169.254.169.254` and `.internal`), sorts **IPv4 addresses before IPv6** (avoiding IPv6 blackhole stalls on dual-stack internet sites), and pins those exact `SocketAddr`s inside `ureq`.
  - **Internet Compatibility & Proxy Routing:** Supports `--proxy`, environment `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` (`resolve_effective_proxy`, `validate_proxy_url`), promotes canonical `www.<apex> <-> <apex>` redirects (`is_allowed_domain`), strips `?query` parameters before `.js`/config classification, skips static `.css`/font/image/video URLs from HTML crawl quotas, passively harvests `/robots.txt`, ingests Stage-0 `--spa-seed` payloads, applies configurable `--jitter-min-ms`..`--jitter-max-ms` + `--wordlist`, logs explicit upstream TCP/TLS/redirect errors and `[NET] Target ... pinned to [...]`, and uses `#[cfg(unix)]` `O_NOFOLLOW` harvest writes for cross-platform builds.
- **How to modify:** Tune crawl limits carefully and keep `PinnedSsrfResolver` + per-hop `verify_url_ssrf_pinned()` intact on any new fetch paths.

#### `src/db.rs` (339 lines), `src/html.rs` (177 lines) & `src/main.rs` (603 lines)
- **What they do:**
  - `db.rs`: WAL persistence, deduplicated `surface_risk_score`, Chrome 124 `stealth_curl_poc` generation, and batch KPI queries.
  - `html.rs`: HTML-escaped rows with CSP-safe `button[data-curl]` buttons and per-row `[.MD]`, `[.DOCX]`, `[.SARIF]`, `[.JSONL]` links plus `hx-swap-oob="innerHTML"` updates.
  - `main.rs`: Supports `--ingest-csv`, `--scan` (`--depth`, `--jitter-min-ms`, `--jitter-max-ms`, `--proxy`, `--categories`, `--wordlist`, `--spa-seed`), `--render`, `--latest-state-json`, `--history-json`, `--categories-json`, and `--compare-scans --scan-a <id> --scan-b <id>`.
- **How to modify:** Keep SQL schema aligned with `001_init_schema.sql` and wire new CLI flags cleanly through `exec_bridge.go`.

---

### 4.5 Go Loopback Gateway & SSRF Firewall (`CodeBase/`)

#### `CodeBase/go.mod`, `CodeBase/webassets.go` & `CodeBase/cmd/gateway/packager.go` (187 lines)
- **What they do:** Moves Go module root to `CodeBase/` with zero external Go dependencies, embeds `web/` into `webassets.EmbeddedWebFS` (`//go:embed all:web`), preserves live disk templates/static reload in dev mode (`resolveWebFS`), supports `--embedded-ui` standalone execution, and implements stdlib `archive/tar` + `compress/gzip` self-contained tarball bundling via `--package-release <out.tar.gz>`.

#### `cmd/gateway/secguard/secguard.go` (392 lines), `secguard_test.go` (133 lines) & `security.go` (39 lines)
- **What they do:** Zero-dependency security library: `EnforceLoopbackAddress`, `IsBlockedIP`, `SanitizeTargetInput` (supporting bracketed public IPv6 literals `[2606:...]`), `ValidateTargetSSRFForScan` & `ParseTargetInputWithOptions` (proxy-aware DNS fallback when proxied while still blocking prohibited/internal targets), `ValidateOutboundProxyWithLookup`, `SanitizeWordlistInput`, `SanitizeCategoriesInput`, `SanitizeFilename`, `ResolveSandboxedPath`, `SanitizeHeaderToken`. All core guards have dedicated unit tests in `secguard_test.go` (zero `[no test files]`).

#### `cmd/gateway/spa_proxy.go` (136 lines)
- **What it does:** Ephemeral loopback (`127.0.0.1:0`) HTTP + `CONNECT` forward proxy for Stage-0 Playwright/Chromium hydration that runs `secguard.ValidateTargetSSRF` and `IsBlockedIP` before dialing outbound so dynamic SPA JS cannot pivot to loopback, RFC 1918, or `169.254.169.254`.

#### `cmd/gateway/main.go` (163 lines) & `cmd/gateway/exec_bridge.go` (624 lines)
- **What they do:**
  - `main.go`: Activates FIPS-140 mode, handles `--embedded-ui` and `--package-release`, binds `127.0.0.1`, logs clear loopback-GUI vs internet-egress separation, and enforces strict CSP (`script-src 'self'`).
  - `exec_bridge.go`: Preserves proxy/TLS CA trust env vars in `scrubbedEnv()`, implements `BatchManager` (`Register`, `Cancel`, `Complete`) driving a bounded `1..4` concurrent target worker pool with `context.WithCancel`, runs Stage-0 SPA hydration when toggled, passes rate-limit/depth/proxy/category/wordlist flags to `dork_spider` (with `180s` timeout), runs Stage-2 `--verify-ast`, cleans `harvestDir`, generates `.md`/`.docx`/`.sarif`/`.jsonl` via `--export-all`, runs cross-platform `runTelemetryStatus` / `runBackupAndSign` (POSIX shell with Python `py_engine.cli` fallback + native Windows support), and emits `batchProgress`, `scanUpdated`, `scanCompleted`, `scanCancelled`, and `scanFailed` SSE events.

#### `cmd/gateway/routes.go` (860 lines)
- **What it does:** Exposes HTTP/HTMX/JSON endpoints backed by `webFS` (`os.DirFS` in dev, `embed.FS` with `--embedded-ui`):
  - `GET /`, `GET /static/*`, `GET /ui/input-mode?mode=single|batch`
  - `POST /api/scan`, `POST /api/scan/{batch_id}/cancel`
  - `GET /api/scans`, `GET /api/scans/compare?a=<id>&b=<id>`, `GET /api/dork-categories`
  - `GET /api/stream-logs-sse` (disables per-connection `WriteTimeout` via `http.NewResponseController` so SSE streams survive idle periods beyond 90s)
  - `GET /panels/svg-telemetry`, `GET /panels/findings`, `GET /telemetry/status`, `POST /api/backup`
  - `GET /api/export/md/{id}`, `/api/export/docx/{id}`, `/api/export/sarif/{id}`, `/api/export/jsonl/{id}`, `/api/export/batch-zip?batch_id=...`

---

### 4.6 Python AST, SPA, Reporting & SBOM Engine (`CodeBase/py_engine/`)

| File | Key Functions / Classes | Purpose & How to Modify |
| :--- | :--- | :--- |
| [`py_engine/cli.py`](CodeBase/py_engine/cli.py) (168 lines) | `main()` | Argparse multiplexer for `--verify-ast`, `--svg`, `--export-md`, `--export-docx`, `--export-sarif`, `--export-jsonl`, `--export-all` (all 4 formats), `--hydrate-spa`, `--telemetry-status`, `--backup-sign`, `--generate-sbom`. |
| [`py_engine/ast_analyzer.py`](CodeBase/py_engine/ast_analyzer.py) (288 lines) | `calculate_shannon_entropy()`, `verify_*()`, `verify_scan_findings_in_db()` | Walks `esprima` JS AST ignoring comments, parses YAML via `SafeLoader`, validates JSON & `lxml`/`BeautifulSoup` DOM, and updates `dork_findings` / `scan_telemetry` / `surface_risk_score`. |
| [`py_engine/report_structured.py`](CodeBase/py_engine/report_structured.py) (241 lines) | `render_sarif_report()`, `render_jsonl_report()`, `write_sarif_report()`, `write_jsonl_report()` | Emits SARIF v2.1.0 (`$schema`, `driver.rules`, `results`, `suppressions`, `invocations`) and streaming NDJSON (`scan_session`, `finding`, `endpoint`) with `CWE-377` symlink guards. |
| [`py_engine/spa_hydrator.py`](CodeBase/py_engine/spa_hydrator.py) (200 lines) | `hydrate_spa_target()`, `write_spa_seed()` | Uses optional Playwright (`chromium`) or system Chrome/Chromium/Edge `--headless --dump-dom --proxy-server=...` via Go's SSRF proxy; falls back cleanly to exit 0 if no browser is installed. |
| [`py_engine/sys_ops.py`](CodeBase/py_engine/sys_ops.py) (89 lines) | `emit_telemetry_status()`, `create_signed_backup()` | Cross-platform Windows & POSIX replacement/fallback for `sys_telemetry.sh` and `backup_and_sign.sh` (`CWE-377` symlink checks + `VACUUM INTO` + SHA-256). |
| [`py_engine/svg_telemetry.py`](CodeBase/py_engine/svg_telemetry.py) (173 lines) | `render_svg_telemetry()` | Orthogonal `SYS.01` `<svg>` KPI & category chart generator. |
| [`py_engine/report_md.py`](CodeBase/py_engine/report_md.py) (285 lines) & [`report_docx.py`](CodeBase/py_engine/report_docx.py) (315 lines) | `write_markdown_report()`, `write_docx_report()` | CyberNest VIDS 5-section Bug Bounty `.md` and Enterprise OpenXML `.docx` generators. |
| [`py_engine/sbom_gen.py`](CodeBase/py_engine/sbom_gen.py) (202 lines) | `generate_sbom_manifests()` | Emits CycloneDX 1.5, SPDX 2.3, and `SBOM.md` with live vendored SHA-256 digests. |

---

### 4.7 Frontend UI (`CodeBase/web/`)

- **`web/templates/index.html` (154 lines) & `partials/*.html` (`input_single.html` 27, `input_batch.html` 30, `scan_options.html` 39):** Renders KPI strip, mode tabs, shared advanced profile accordion (max depth, concurrent workers, jitter min/max ms, outbound HTTP proxy, catalog category browser, custom wordlist, SPA hydration toggle), batch progress track + `[ABORT BATCH]` button, historical scan selector + scan diff controls (`[COMPARE]`), and export bar (`.MD`, `.DOCX`, `.SARIF`, `.JSONL`, `BATCH .ZIP`, `VACUUM + SHA256 LOCK`).
- **`web/static/css/synth-ledger.css` (546 lines):** Enforces strict `0px` orthogonal geometry (`SYS.01`), monospace tabular alignment, and styles progress meters, accordions, and diff cards.
- **`web/static/js/autodorker-ui.js` (395 lines):** Handles `EventSource` (`connected`, `log`, `batchProgress`, `scanUpdated`, `scanCompleted`, `scanCancelled`, `scanFailed`), `POST /api/scan/{batch_id}/cancel`, `/api/scans`, `/api/scans/compare`, `/api/dork-categories` interactive chips, dynamic export button synchronization, and clipboard copy — all strictly under `script-src 'self'` with zero inline JS.

---

### 4.8 Automated Test Suites (`CodeBase/tests/` & Gateway)

| Test Suite File | Verified Scope | How to Extend / Run |
| :--- | :--- | :--- |
| [`CodeBase/tests/test_dork_ast.rs`](CodeBase/tests/test_dork_ast.rs) (517 lines) | All 295 `DorkSet.csv` rules (`32` chain + `263` atomic), WAL ingest roundtrip, Shannon entropy, Gate 0/1/2 FP suppression, cross-asset `[CHAIN]` correlation (`.git` + `robots.txt` + Swagger + login), `PinnedSsrfResolver` + `www.` redirect scope + proxy/CGNAT/IPv4-mapped IPv6 blocking, and **5,500-iteration deterministic property-based fuzz test** on `dork_ast` + `ast_verifier`. | `cd CodeBase/crates/dork_spider && cargo test --locked` |
| [`CodeBase/cmd/gateway/secguard/secguard_test.go`](CodeBase/cmd/gateway/secguard/secguard_test.go) (133 lines), [`security_test.go`](CodeBase/cmd/gateway/security_test.go) (57 lines) & [`tests/test_security_ssrf.go`](CodeBase/tests/test_security_ssrf.go) | Loopback bind checks, IPv6 `[...]` normalization, CGNAT/mapped-IPv6/metadata blocking, proxy/wordlist/category validation, Stage-0 loopback SPA SSRF proxy blocking (`403` on internal/metadata), CSV/multi-URL parsing, and symlink escape guards. | `cd CodeBase/cmd/gateway && go test -v ./...` and `cd CodeBase/tests && go test -v ./...` |
| [`CodeBase/tests/test_exports_e2e.py`](CodeBase/tests/test_exports_e2e.py) (558 lines) | Python `esprima`/YAML/HTML/entropy analyzers; `.md`, `.docx`, SARIF v2.1.0, `.jsonl` generation; Python telemetry & signed `VACUUM INTO` backups; SPA hydrator fallback; live Gateway E2E batch concurrency across `Targ001`/`Targ002`, ZIP verification, `/api/scans`, `/api/scans/compare`, `/api/dork-categories`, `/api/scan/*/cancel`, `--package-release` tar.gz inspection, and `--embedded-ui` isolated execution. | `cd CodeBase && ./dev.sh simulate` or `.venv/bin/python -m unittest discover -s tests -p "test_*.py" -v` |

---

## 5. Deployed & Verified Functional Inventory (v2.0 Current State)

### Outbound Internet Egress + All P0 / P1 / P2 Items Completed
- **GUI on Loopback (`127.0.0.1`) + Outgoing Scans Over Internet:** Verified live internet scan execution (`https://www.example.com/`) through `127.0.0.1` Gateway + `PinnedSsrfResolver` (IPv4-first DNS pinning, canonical `www.` <-> apex redirect allowance, proxy/CA env preservation, infinite SSE deadline, query-stripped asset bucketing, static asset filtering, and clear `[GUI: 127.0.0.1] [EGRESS: INTERNET]` telemetry).
- **P0 #1 Cross-Asset `[CHAIN]` Correlator:** Implemented in `ast_verifier.rs` and verified via `test_cross_asset_chain_correlation`.
- **P0 #2 Optional Stage-0 SPA Hydration:** Implemented via `spa_proxy.go` + `py_engine/spa_hydrator.py` + `spider.rs --spa-seed` + `spa_hydrate` UI toggle.
- **P0 #3 Interactive Scan History & Diff UI:** Implemented via `--history-json`/`--compare-scans` in `main.rs`, `/api/scans` & `/api/scans/compare` in `routes.go`, and History/Diff UI controls in `index.html` + `autodorker-ui.js`.
- **P1 #4 SARIF v2.1.0 & JSON-Lines Exports:** Implemented in `py_engine/report_structured.py`, `cli.py`, `routes.go`, `html.rs`, `index.html`, and `--export-all` / Batch `.ZIP`.
- **P1 #5 Configurable Rate-Limit, Depth, Proxy, Category & Wordlist Controls:** Implemented in `scan_options.html`, `secguard.go`, `exec_bridge.go`, `main.rs`, and `spider.rs`.
- **P1 #6 Windows Cross-Platform Telemetry & Backup Parity:** Implemented in `py_engine/sys_ops.py`, `exec_bridge.go`, and `dev.bat`.
- **P1 #7 Outbound Redirect & Custom DNS Pinning:** Implemented via `PinnedSsrfResolver` inside `spider.rs`.
- **P2 #8 Concurrent Bounded Batch Queue & Cancellation:** Implemented via `BatchManager` (`exec_bridge.go`), `POST /api/scan/{batch_id}/cancel`, and live SSE progress bar.
- **P2 #9 Dedicated `secguard/` Unit Tests & Property Fuzzing:** Implemented in `secguard_test.go` and `test_property_fuzz_dork_ast_and_verifier` (5,500 adversarial AST/verifier cases).
- **P2 #10 Self-Contained Release Packaging (`archive/tar` + `embed.FS`):** Implemented in `CodeBase/go.mod`, `webassets.go`, `packager.go`, `--embedded-ui`, `--package-release`, and `./dev.sh package`.

### Observed Verification Baseline
- **Rust (`cargo test --locked`):** `8/8` passed (including `[CHAIN]` correlator, `PinnedSsrfResolver`, and 5,500-case property fuzz test).
- **Go (`go test -v ./...` across `cmd/gateway`, `cmd/gateway/secguard`, `tests`):** `12/12` passed (`3/3` gateway + SPA proxy, `5/5` `secguard`, `4/4` integration SSRF), zero `[no test files]` packages.
- **Python & Live Full-Stack E2E (`tests.test_exports_e2e`):** `2/2` passed, exercising AST gates, `.md`/`.docx`/`.sarif`/`.jsonl`/`.zip`, history/compare/categories/cancel APIs, SPA fallback, `--package-release` tar.gz inspection, and `--embedded-ui` mode.
- **CLI, Packaging & Live Internet Audit:** `./dev.sh cli` verified DB WAL status + SHA-256 `VACUUM INTO` snapshot; `./dev.sh package` generated a 7.7M standalone release `.tar.gz`; isolated live internet test against `https://www.example.com/` via `127.0.0.1` Gateway completed with `status: COMPLETED`, `dorks_evaluated: 295`, pinned public IPv4/IPv6 telemetry, and SARIF v2.1.0 output.

---

## 6. Operational Commands & Environment Overrides

```bash
cd CodeBase

./dev.sh setup                  # Check go/cargo/rustc/python3, build .venv, create runtime dirs
./dev.sh build                  # Build Rust release + Go FIPS-140 binaries, seed DorkSet.csv, refresh SBOMs
./dev.sh test                   # Execute Rust + Go (all 3 packages) + Python E2E test suites
./dev.sh cli                    # Seed DB, check WAL status, run SHA-256 VACUUM INTO snapshot
./dev.sh cli <url>              # Headless CLI audit outputting JSON telemetry
./dev.sh simulate               # Run ephemeral mock HTTP + live Gateway + AST + Export E2E suite
./dev.sh package [out.tar.gz]   # Bundle standalone archive/tar release with embedded UI
./dev.sh run                    # Launch loopback gateway at http://127.0.0.1:8090
./dev.sh fmt                    # Format Rust and Go source files
```

### Supported Environment Variables & Gateway Flags
- `AUTODORKER_BIND_ADDR` / `--bind` — Loopback bind host:port for GUI (default `127.0.0.1:8090`, must pass `EnforceLoopbackAddress`). Outgoing target scans traverse the internet independently unless `local_staging` is toggled.
- `AUTODORKER_DB_PATH` — Override SQLite3 WAL database location (default `CodeBase/data/autodorker_state.db`).
- `AUTODORKER_OUTPUT_DIR` — Override artifact staging root (default `CodeBase/data/Output`).
- `AUTODORKER_BACKUP_DIR` — Override `VACUUM INTO` snapshot directory (default `CodeBase/data/backups`).
- `AUTODORKER_DORKSET_PATH` — Override CSV rule catalog path (default `../Docs/DorkSet.csv`).
- `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` — Preserved cleanly across `scrubbedEnv()` and validated for SSRF safety before outbound scans.
- Gateway binary flags: `--embedded-ui` (force serve from Go `embed.FS`) and `--package-release <out.tar.gz>` (emit release tarball and exit).

---

## 7. Next Engineering ToDos (Roadmap v2.1)

The following **3 new ToDo items** capture the next recommended engineering enhancements for AutoDorker:

1. **TLS/X.509 Certificate Surface Inspection & Passive SAN/Subdomain Enumeration (`P0`):** Inspect negotiated HTTPS certificate chains during live internet scans (extracting Subject Alternative Names, issuer CN, expiration proximity, and weak signature algorithms), store TLS findings cleanly alongside `scan_telemetry`, and optionally feed discovered in-scope SAN hostnames into batch recon queues.
2. **Authenticated Staging Profiles & Path Exclusion Scope Rules (`P1`):** Add ephemeral session authentication headers (`Cookie`, `Authorization: Bearer ...` held strictly in memory inside `ScanRequestConfig` and scrubbed from disk, SQLite, and logs) plus user-supplied exclude-path regexes (e.g., `/logout`, `/signout`, `/delete`) so authorized staging engagements can safely audit authenticated portals.
3. **Scheduled Drift Audits & Alert Dispatchers (`P2`):** Add an opt-in background scan scheduler inside the Go gateway (`BatchManager`) that periodically re-audits saved targets, runs `--compare-scans` against the prior baseline automatically, and emits local SSE alerts or signed JSON webhook payloads whenever `added_count > 0` or `risk_delta > 0`.
