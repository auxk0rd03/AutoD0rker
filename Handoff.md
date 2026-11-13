# AutoDorker — Enterprise Handoff & Engineering Reference Manual

**Document Classification:** Internal Engineering Handoff // Defensive Security Tooling  
**Organization:** CyberNest Holdings LLC — CyberNest Labs Department  
**Compliance Baselines:** `CN-LABS-H2C-2026-01`, `CN-LABS-BRW-2026-02`, `CN-DIR-2026-004`, CMMC 2.0 Level 2  
**Architecture Stack:** **RPGS** (**R**ust + **P**ython + **G**o + POSIX **S**hell) + **SQLite3 (WAL Mode)** + **HTMX 2.0** (`SYS.01 NOCTURNAL SYNTH-LEDGER`)  

---

## 1. Executive Summary & Architectural Design

**AutoDorker** is a local-first, air-gap-capable autonomous web-surface auditing and dork verification platform engineered from [Docs/AutoDorkerDevDoc.md](Docs/AutoDorkerDevDoc.md). Instead of forwarding target reconnaissance telemetry to external search engines, AutoDorker compiles all **295 signatures** in [Docs/DorkSet.csv](Docs/DorkSet.csv) (**32 `[CHAIN]` rules** and **263 atomic rules**) into a typed **Boolean Dork Abstract Syntax Tree (AST)** and executes deterministic local verification directly against harvested HTTP, DOM, JavaScript, JSON, YAML, SQL, and configuration assets.

### Polyglot Responsibility Matrix (RPGS)

1. **`[R]` Rust Execution Engine (`CodeBase/crates/dork_spider/`)**
   - Compiles Google Dork syntax (including real-world GHDB quirks) into `DorkExpr` ASTs and synthesizes active probe paths (`inurl:`, `ext:`, `filetype:`, quoted phrases).
   - Executes a bounded breadth-first spider (`MAX_HTML_PAGES = 25`, `MAX_JS_FILES = 50`, `MAX_CONFIG_FILES = 50`, `MAX_ACTIVE_PROBES = 45`) with **6-pillar L7 stealth impersonation** (Chrome 124 headers, jittered worker pool, WAF detection & circuit breaker, Soft-404 baseline fingerprinting).
   - Evaluates **Stage-1 Gate 0/1/2 verification** (64-bit DOM Tag SimHash Soft-404 suppression, structural DOM/JS/Config checks, and Shannon entropy `H(X)` in integer basis points to eliminate float drift and placeholder keys).
   - Persists sessions, telemetry, endpoints, and verified findings into **SQLite3 WAL** and emits HTML-escaped HTMX `hx-swap-oob="true"` table/KPI fragments.

2. **`[P]` Python AST & Deliverable Engine (`CodeBase/py_engine/`)**
   - Performs **Stage-2 deep syntactic verification** using `esprima` (ECMAScript AST walker), `pyyaml` (`SafeLoader`), `lxml`, and `BeautifulSoup4`.
   - Renders server-side orthogonal flat `<svg>` visual telemetry (`SYS.01` palette, zero rounded corners).
   - Generates **CyberNest VIDS Bug Bounty Markdown (`.md`)** and **Enterprise Microsoft Word (`.docx`)** reports complete with CVSS v3.1 metadata, redacted AST snippets, chained impact analysis, and copy-paste **Chrome 124 Stealth `curl` PoCs**.
   - Auto-generates CycloneDX 1.5 (`SBOM.cyclonedx.json`), SPDX 2.3 (`SBOM.spdx.json`), and human-readable (`SBOM.md`) manifests on build.

3. **`[G]` Go Loopback Gateway & Security Firewall (`CodeBase/cmd/gateway/`)**
   - Zero-external-dependency Go 1.24+ HTTP server compiled with `//go:debug fips140=on` (`GOFIPS=1 GOFIPS140=v1.0.0`).
   - Enforces **strict loopback binding (`127.0.0.1:8090`**, scanning `8000–8100` if busy), strict local Content Security Policy (`script-src 'self'`, zero external CDNs), and **SSRF defense** (`secguard`) blocking RFC 1918, loopback (unless explicitly toggled in Local Staging Mode), CGNAT (`100.64.0.0/10`), link-local, IPv6 ULA (`fc00::/7`), and unconditional cloud metadata `169.254.169.254`.
   - Multiplexes Rust, Python, and POSIX Shell workers under a **scrubbed environment** (`PATH`, `HOME`, `TMPDIR`, `LANG`, `LC_ALL`, `AUTODORKER_DB_PATH` only), streams real-time stderr telemetry over **Server-Sent Events (`/api/stream-logs-sse`)**, enforces **Zero-Footprint harvest cleanup**, and streams in-memory multi-target **Batch `.zip`** archives.

4. **`[S]` POSIX Shell & Windows Parity (`CodeBase/dev.sh`, `dev.bat`, `scripts/`)**
   - Implements unified `CN-DIR-2026-004` commands (`setup`, `build`, `run`, `serve`, `cli`, `simulate`, `test`, `fmt`).
   - Enforces `CWE-377` symlink refusal + `0700`/`0600` file permissions and `CWE-114` PID locking.
   - Polls live SQLite3 WAL health (`scripts/sys_telemetry.sh`) and executes atomic `VACUUM INTO` backups signed with truncated SHA-256 audit hashes (`scripts/backup_and_sign.sh`).

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
    ├── dev.bat                              # Windows 10/11 CLI parity orchestrator
    ├── dev.sh                               # POSIX / Linux CLI orchestrator (CN-DIR-2026-004)
    ├── launcher.bat                         # Interactive Windows menu wrapper
    ├── launcher.sh                          # Interactive POSIX menu wrapper
    ├── requirements.txt                     # Pinned Python 3 AST, DOM & DOCX dependencies
    ├── bin/
    │   └── .gitkeep                         # Staging folder for compiled dork_spider & gateway
    ├── cmd/
    │   └── gateway/
    │       ├── exec_bridge.go               # Scrubbed subprocess IPC & scan pipeline orchestrator
    │       ├── go.mod                       # Go module (stdlib only, zero third-party Go deps)
    │       ├── main.go                      # Loopback listener, CSP headers, FIPS-140 mode, graceful shutdown
    │       ├── routes.go                    # HTTP/HTMX routes, SSE hub, batch ZIP streamer
    │       ├── security.go                  # Package-local wrappers delegating to secguard
    │       ├── security_test.go             # Gateway unit tests for loopback & SSRF guards
    │       └── secguard/
    │           └── secguard.go              # SSRF IP filter, target parser/sanitizer, sandboxed paths
    ├── crates/
    │   └── dork_spider/
    │       ├── Cargo.lock                   # Reproducible Rust crate dependency lockfile
    │       ├── Cargo.toml                   # Rust 2024 crate manifest (LTO release profile)
    │       └── src/
    │           ├── ast_verifier.rs          # Gate 0 SimHash, Gate 1 AST checks, Gate 2 entropy checks
    │           ├── db.rs                    # SQLite3 WAL persistence, risk scoring, cURL PoC builder
    │           ├── dork_ast.rs              # Lexer, recursive-descent Dork AST compiler & probe synthesizer
    │           ├── entropy.rs               # Shannon H(X), 64-bit DOM Tag SimHash, redaction & placeholders
    │           ├── html.rs                  # Escaped HTMX table row & hx-swap-oob KPI emitter
    │           ├── lib.rs                   # Crate module exports
    │           ├── main.rs                  # Rust CLI entrypoint (--ingest-csv, --scan, --render, --latest-state-json)
    │           └── spider.rs                # 6-pillar stealth BFS crawler, Webpack/Vite chunk parser, worker pool
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
    │   ├── cli.py                           # Python CLI (--verify-ast, --svg, --export-*, --generate-sbom)
    │   ├── report_docx.py                   # Pure OpenXML Enterprise Word (.docx) generator
    │   ├── report_md.py                     # CyberNest VIDS Bug Bounty Markdown (.md) generator
    │   ├── sbom_gen.py                      # Deterministic CycloneDX/SPDX/Markdown SBOM builder
    │   └── svg_telemetry.py                 # Server-side orthogonal SYS.01 <svg> bar chart emitter
    ├── scripts/
    │   ├── backup_and_sign.sh               # VACUUM INTO snapshot + SHA-256 audit badge
    │   └── sys_telemetry.sh                 # Top-bar WAL health & active rule telemetry check
    ├── tests/
    │   ├── go.mod                           # Standalone Go test module linked to ../cmd/gateway
    │   ├── ssrf_runner_test.go              # Test runners invoking test_security_ssrf.go checks
    │   ├── test_dork_ast.rs                 # Rust integration tests (AST, 295 rules, WAL, entropy, soft-404)
    │   ├── test_exports_e2e.py              # Python & full-stack Gateway/Rust/AST/.MD/.DOCX/.ZIP E2E tests
    │   └── test_security_ssrf.go            # Multi-URL/CSV, injection, SSRF & symlink traversal guards
    └── web/
        ├── static/
        │   ├── css/
        │   │   └── synth-ledger.css         # SYS.01 NOCTURNAL SYNTH-LEDGER stylesheet (0px radius)
        │   ├── fonts/
        │   │   └── JetBrainsMono.woff2      # Vendored local monospace font (v2.304)
        │   └── js/
        │       ├── autodorker-ui.js         # SSE EventSource listener, mode tabs, curl clipboard handler
        │       └── htmx.min.js              # Vendored local HTMX v2.0.4 (zero external CDNs)
        └── templates/
            ├── index.html                   # Primary single-page dashboard template
            └── partials/
                ├── input_batch.html         # HTMX partial: Multi-URL / .CSV upload mode
                └── input_single.html        # HTMX partial: Single URL scan mode
```

**Note on Excluded Artifacts:** `.gitignore` strictly excludes `.venv/`, `CodeBase/bin/dork_spider`, `CodeBase/bin/gateway`, `CodeBase/crates/dork_spider/target/`, SQLite runtime files (`*.db`, `*.db-wal`, `*.db-shm`, `*.db-journal`), `CodeBase/data/backups/*`, `CodeBase/data/Output/*`, runtime `.pid`/`.log` files, temporary `adk_harvest_*` directories, and credential extensions (`.env`, `.pem`, `.key`, `.jks`).

---

## 3. End-to-End Runtime Data Flow

```mermaid
flowchart LR
    UI["SYS.01 Web UI (HTMX 2.0 + SSE)"] -->|"POST /api/scan"| GW["Go Gateway (127.0.0.1:8090 // FIPS-140)"]
    GW -->|"secguard.ParseTargetInput"| VAL{"SSRF & Injection Guard"}
    VAL -->|"Rejected (400)"| UI
    VAL -->|"Clean Targets + adk_harvest_*"| RS["Rust dork_spider (--scan --keep-harvest)"]
    RS -->|"6-Pillar Stealth BFS + Active Probes"| TGT["Authorized Target(s)"]
    TGT -->|"HTTP/HTML/JS/Config"| RS
    RS -->|"Gate 0/1/2 AST + Shannon H(X)"| DB[("SQLite3 WAL DB")]
    RS -->|"Live stderr stream"| SSE["SSEHub -> /api/stream-logs-sse"]
    SSE --> UI
    GW -->|"Stage-2 Check"| PY1["Python ast_analyzer.py (--verify-ast)"]
    PY1 -->|"esprima / pyyaml / lxml updates"| DB
    GW -->|"os.RemoveAll(harvestDir)"| ZF["Zero-Footprint Purge"]
    GW -->|"Generate Reports"| PY2["Python report_md / report_docx (--export-all)"]
    PY2 -->|"Output/TargXXX/*.md & *.docx"| DB
    GW -->|"VACUUM INTO + SHA256"| SH["scripts/backup_and_sign.sh"]
    GW -->|"scanUpdated / scanCompleted"| UI
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

#### `CodeBase/dev.sh` (169 lines) & `CodeBase/launcher.sh` (34 lines)
- **What it does:** Implements `CN-DIR-2026-004` subcommands: `setup`, `build`, `run`/`serve`, `cli [url]`, `simulate`, `test`, `fmt`. Auto-adds `/usr/local/go/bin` to `PATH` when `go` is absent from default `PATH`. `init_secure_runtime_dir()` blocks symlinks (`[ -L ... ]` for `CWE-377`), enforces `0700` on `~/.cache/autodorker`, `umask 0077`, and PID locking (`gateway.pid` for `CWE-114`). `cmd_build()` builds Release Rust (`cargo build --release`), builds FIPS-140 Go (`GOFIPS=1 GOFIPS140=v1.0.0 go build -ldflags="-s -w"`), ingests `DorkSet.csv`, and regenerates SBOMs.
- **How to modify:** Edit `BIND_ADDR`, `DB_PATH`, or `DORK_CSV` default fallbacks near lines 17–19 (overridable via `AUTODORKER_BIND_ADDR`, `AUTODORKER_DB_PATH`, `AUTODORKER_DORKSET_PATH`). Mirror any new subcommands in both `dev.bat` and `launcher.sh`/`launcher.bat`.

#### `CodeBase/dev.bat` (124 lines), `CodeBase/launcher.bat` (25 lines) & `CodeBase/Makefile` (28 lines)
- **What they do:** `dev.bat` and `launcher.bat` provide Windows 10/11 command parity using `%LOCALAPPDATA%\autodorker` and `.venv\Scripts\`. `Makefile` exposes `make setup|build|run|serve|cli|simulate|test|fmt|clean` delegating directly to `./dev.sh`.
- **How to modify:** Keep `dev.bat` subcommand labels (`cmd_setup`, `cmd_build`, etc.) aligned 1:1 with `dev.sh`.

#### `CodeBase/scripts/sys_telemetry.sh` (36 lines)
- **What it does:** Emits the compact `SYS.01` top-bar HTML telemetry badge (`[DB: WAL_OK // ... KB] [DORKS: 295_ACTIVE // 32_CHAIN] [SYNC: HH:MM:SS UTC] [LOOPBACK: 127.0.0.1]`). Refuses symlinked DB files (`CWE-377`). Uses `sqlite3` CLI when present or seamlessly falls back to `.venv/bin/python` stdlib `sqlite3`.
- **How to modify:** Keep output strictly bounded to inline HTML `<span class="val-...">` badges with zero `<script>` tags to satisfy Gateway CSP and HTMX swap formatting.

#### `CodeBase/scripts/backup_and_sign.sh` (45 lines)
- **What it does:** Validates non-symlink DB and backup paths (`CWE-377`), enforces `0700` directory and `0600` file modes, executes atomic `VACUUM INTO 'data/backups/autodorker_snapshot_<UTC>.db'` (via `sqlite3` or Python fallback), computes the first 12 hex characters of SHA-256 (`sha256sum` / `shasum -a 256`), and emits `[AUDIT_LOCK: YYYYMMDD_HHMMSS // SHA256:<prefix>]`.
- **How to modify:** Adjust snapshot retention or signature length here; also update any tests expecting `[AUDIT_LOCK:` format.

---

### 4.3 Database Migration Schema (`CodeBase/data/migrations/`)

#### `CodeBase/data/migrations/001_init_schema.sql` (98 lines)
- **What it does:** Initializes SQLite3 WAL performance pragmas (`journal_mode = WAL`, `synchronous = NORMAL`, `temp_store = MEMORY`, `mmap_size = 268435456`, `cache_size = -64000`, `foreign_keys = ON`) and five tables:
  1. `dork_catalog` — Stores all compiled `DorkSet.csv` rules with `compiled_ast_json`, `is_chain`, `default_severity`, and `cwe_id`.
  2. `scan_sessions` — Tracks single/batch scans (`batch_id`, `batch_index`, `target_url`, `target_host_hash`, `scan_profile` in `STEALTH_PASSIVE|ACTIVE_VERIFICATION`, `shadow_mode`, `surface_risk_score`, `baseline_404_simhash`, `detected_waf_vendor`, `status`, `output_dir_rel`).
  3. `dork_findings` — Verified and Shadow-mode findings using integer **basis points (`_bps`)** (`cvss_score_bps`, `shannon_entropy_bps`, `confidence_bps`) for cross-language numeric determinism, `exact_dedup_hash` (`UNIQUE`), `ast_node_type`, redacted `ast_context_snippet`, and `stealth_curl_poc`.
  4. `scan_telemetry` — Asset counters, FP drop counters (`ast_fp_dropped`, `soft404_fp_dropped`, `entropy_fp_dropped`), latency mean, baseline entropy, category breakdown JSON, and vendor/tech observations.
  5. `harvested_endpoints` — Unique discovered endpoints (`UNIQUE(scan_id, endpoint_url)`), status codes, and third-party vendor flags.
- **How to modify:** Add sequential `002_*.sql` migrations or extend `001_init_schema.sql` while updating `crates/dork_spider/src/db.rs` (`include_str!("../../../data/migrations/001_init_schema.sql")`) and Python queries in `py_engine/`. Keep `_bps` columns as SQLite `INTEGER`.

---

### 4.4 Rust Execution Engine (`CodeBase/crates/dork_spider/`)

- `Cargo.toml` (37 lines) & `src/lib.rs` (6 lines): Configures Rust 2024 edition crate `dork_spider`, release LTO (`opt-level = 3`, `lto = true`, `strip = true`), bundled SQLite (`rusqlite = 0.32`), `ureq = 2.10` (TLS+gzip), `scraper = 0.21`, `regex`, `csv`, `sha2`, `serde`, `rand`, `chrono`, `url`.

#### `src/dork_ast.rs` (706 lines)
- **What it does:** Lexes and parses arbitrary Google Dork syntax into `DorkExpr` (`Term(DorkOperator)`, `Not`, `And`, `Or`) using recursive descent.
  - Handles real-world GHDB quirks found in `DorkSet.csv` (balanced quotes, tight binding of `|` vs whitespace, leading `-` negations, `+`, `,`, `OR`/`AND`, aliases `allinurl:`/`inurl:`, `allintitle:`/`intitle:`, `allintext:`/`intext:`, `ext:`/`filetype:`, `site:`).
  - `synthesize_probe_paths(expr)` extracts actionable path/file probes from positive AST terms while honoring `Not` exclusion branches.
  - `classify_dork_rule(category, raw_dork)` assigns initial severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) and `CWE-*` identifiers across all 13 `DorkSet.csv` categories.
- **How to modify:** To support new operators (e.g., `cache:`, `related:`, `inanchor:`), extend `is_operator_name()`, add a variant to `DorkOperator`, implement its probe generation in `synthesize_probe_paths()`, and implement evaluation in `ast_verifier.rs`. Re-run `cargo test --locked`.

#### `src/entropy.rs` (231 lines)
- **What it does:**
  - `shannon_entropy()` / `shannon_entropy_bps()`: Computes Shannon entropy $H(X) = -\sum p(x_i)\log_2 p(x_i)$ and returns deterministic integer basis points (e.g., `3.42` bits/char = `342`).
  - `dom_tag_simhash()` & `simhash_similarity_bps()`: Computes 64-bit structural DOM SimHash (FNV-1a weighted over HTML tag unigrams and opening tag bigrams) and Hamming similarity in basis points (0–10000).
  - `is_placeholder_secret()`, `redact_secret()`, `evaluate_secret_candidates()`: Detects AWS access keys (`AKIA`/`ASIA` + 16 chars), Google keys (`AIza`), Stripe keys (`sk_live_`/`pk_live_`), GitHub tokens (`ghp_`/`gho_`/`github_pat_`), JWTs, OpenSSH private key blocks, and generic assignments. Drops dummy placeholders (`AKIAXXXXXXXXXXXXXXXX`, `YOUR_API_KEY_HERE`, `changeme123`) below entropy thresholds (`3.00` bps `300` for fixed-alphabet AWS keys, `3.20` bps `320` for general keys) and masks secrets before DB storage (`prefix...suffix`).
- **How to modify:** Tune placeholder substrings in `is_placeholder_secret()` or add new token regexes inside `evaluate_secret_candidates()`. Remember that literals resembling real keys in unit tests should be constructed dynamically (`concat!`) to avoid upstream push-protection false positives.

#### `src/ast_verifier.rs` (823 lines)
- **What it does:** Implements the Dual-Gate Structural & Entropy Verifier over `HarvestedDoc`:
  - `build_harvested_doc()`: Classifies fetched MIME/paths into `DocKind` (`Html`, `JavaScript`, `Json`, `Yaml`, `Config`, `Sql`, `Log`, `Text`), parses HTML DOM with `scraper` (extracting `<title>`, visible text, `<input type="password">` / login forms, Apache/Nginx directory index structures, outbound links), strips JS comments (`/*...*/` and `//`) and extracts `(key, value)` variable/object assignments, validates JSON/YAML key-value syntax, and marks CDN/vendor assets (`VENDOR_PATTERNS`: `akamai`, `tiqcdn`, `tealium`, `adobe`, `demdex`, `google-analytics`, `googletagmanager`, `doubleclick`).
  - `verify_rules_against_docs()`:
    - **Gate 0 (Soft-404 Filter):** Drops non-explicit 200 HTML pages whose SimHash similarity to the site's 404 probe baseline is `>= 9200` bps (`92%`) without structural directory-index markers (`soft404_fp_dropped`).
    - **Gate 1 (AST Evaluator):** Evaluates `DorkExpr` against structured DOM/URL/JS/Config nodes (`DOM_DIR_INDEX`, `DOM_LOGIN_FORM`, `DOM_TITLE`, `DOM_VISIBLE_TEXT`, `JS_OBJ_PROP`, `YAML_KEY`, `JSON_KEY`, `SQL_DDL_DUMP`, `LOG_TRACEBACK`), translating external `site:` rules locally (`ast_fp_dropped`).
    - **Gate 2 (Entropy & Shadow Mode):** Validates secret entropy `>= 300`/`320` bps; suppresses low-entropy candidates in normal mode (`entropy_fp_dropped`) or preserves them downgraded as `INFO` with `is_suppressed_fp = 1` when `--shadow` is active. Vendor CDN hits are downgraded to `INFO`.
- **How to modify:** Adjust Soft-404 similarity threshold (`9200`), severity/CVSS mapping (`cvss_for_severity`), or add new structural predicates in `eval_operator()`.

#### `src/spider.rs` (856 lines)
- **What it does:** Executes the bounded, hardened crawl and active probe stage:
  - **Bounds:** `MAX_HTML_PAGES = 25`, `MAX_JS_FILES = 50`, `MAX_CONFIG_FILES = 50`, `MAX_ACTIVE_PROBES = 45`, `PROBE_CONCURRENCY_LIMIT = 2`, `PROBE_JITTER_MIN_MS = 250`, `PROBE_JITTER_MAX_MS = 750`, `WAF_COOLDOWN_MS = 1500`.
  - **6-Pillar Stealth Persona:** Injects `CHROME_UA`, `Sec-Ch-Ua`, `Sec-Ch-Ua-Mobile`, `Sec-Ch-Ua-Platform`, `Sec-Fetch-Dest`, `Sec-Fetch-Mode`, `Sec-Fetch-Site`, `Accept`, `Accept-Language`, and optional sanitized `X-Security-Engagement` (`sanitize_header_val()`).
  - **SSRF & Domain Scoping:** `verify_url_ssrf()` and `is_blocked_ip()` filter resolved DNS IPs on initial fetch AND redirect hops; `is_allowed_domain()` prevents off-domain spider runaway while logging third-party scripts as vendor assets.
  - **Bundler Discovery:** `extract_bundler_chunks()` parses Webpack (`__webpack_require__.p` + numeric/named chunk maps), Vite, and Rollup asset references inside fetched JS bundles.
  - **Baseline & WAF Circuit Breaker:** Requests `/_adk_baseline_404_<rand>` to capture baseline latency, 404 SimHash, and 404 entropy; aborts active probing upon Cloudflare/Akamai/Imperva/F5 ASM/ModSecurity `403`/`429`/`503` triggers (`detected_waf_vendor`, `waf_tripped`).
  - **Hardened Harvest I/O:** Creates `0o700` harvest temp dirs and uses `O_NOFOLLOW` on Unix to defeat symlink races (`CWE-377`).
- **How to modify:** Increase crawl caps carefully via top-level `pub const` values. Keep `O_NOFOLLOW` and `verify_url_ssrf()` intact on any new fetcher functions.

#### `src/db.rs` (339 lines), `src/html.rs` (175 lines) & `src/main.rs` (312 lines)
- **What they do:**
  - `db.rs`: Opens WAL connections (`open_wal_db`, 5s busy timeout), performs idempotent upserts in `TransactionBehavior::Immediate`, computes deduplicated `surface_risk_score` (`0–100`), constructs full multi-header Chrome 124 `stealth_curl_poc` commands, and aggregates batch KPIs (`query_batch_kpis`).
  - `html.rs`: Escapes all attacker-controlled strings (`escape_html`) and emits `<tbody>` rows plus `<div id="kpi-*" hx-swap-oob="true">` OOB swap blocks.
  - `main.rs`: Parses `--ingest-csv`, `--scan`, `--render`, and `--latest-state-json`; drives stdout JSON telemetry and structured stderr log streaming for Go's SSE hub.
- **How to modify:** Any new CLI flag added to `main.rs` should also be wired cleanly in `cmd/gateway/exec_bridge.go` (`executeScanPipeline`). Note Rust Edition 2024 reserves the keyword `gen` (use `r#gen` as in `spider.rs`).

---

### 4.5 Go Loopback Gateway & SSRF Firewall (`CodeBase/cmd/gateway/`)

#### `cmd/gateway/secguard/secguard.go` (281 lines) & `cmd/gateway/security.go` (23 lines)
- **What it does:** Zero-dependency security enforcement library:
  - `EnforceLoopbackAddress()`: Refuses startup if `--bind` / `AUTODORKER_BIND_ADDR` resolves to anything other than `127.0.0.1` / `::1`.
  - `IsBlockedIP()`: Blocks RFC 1918, loopback (unless `allowLocalStaging = true`), CGNAT `100.64.0.0/10`, link-local, unspecified/multicast, IPv6 ULA `fc00::/7`, and **unconditionally blocks cloud metadata `169.254.169.254`** even when `allowLocalStaging = true`.
  - `SanitizeTargetInput()` & `ParseTargetInputWithLookup()`: Rejects shell metacharacters (`[;|&$`()<>\x00\r\n]`), whitespace/tabs, leading `-` CLI flag injection, `..` or `\`, and non-HTTP(S) schemes; splits `url1,url2,url3` / newline CSV lists, skips CSV headers (`url`, `target`, `domain`), and deduplicates clean targets.
  - `SanitizeFilename()` & `ResolveSandboxedPath()`: Clamps filenames (`[A-Za-z0-9._-]`), resolves symlinks via `filepath.EvalSymlinks`, and proves child containment within `baseDir`.
  - `SanitizeHeaderToken()`: Strips CR/LF/NUL and filters header characters for `X-Security-Engagement`.
- **How to modify:** Put testable pure logic inside `secguard` (with dependency injection like `ParseTargetInputWithLookup`) so both gateway and `CodeBase/tests/` can test without spawning network sockets.

#### `cmd/gateway/main.go` (128 lines)
- **What it does:** Activates `//go:debug fips140=on`, reports `crypto/fips140.Enabled()` (`FIPS-140-3_ACTIVE` vs `STANDARD`), binds `127.0.0.1:8090` (scanning `8000–8100` on port collision), wraps routes with `strictLocalSecurityHeaders` (`Content-Security-Policy: ... script-src 'self' ... frame-ancestors 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`), auto-seeds `DorkSet.csv` on empty DB startup, and handles `SIGINT`/`SIGTERM` graceful shutdown.
- **How to modify:** Keep `script-src 'self'` strict—never introduce inline scripts or remote CDNs.

#### `cmd/gateway/exec_bridge.go` (342 lines)
- **What it does:**
  - Resolves `AppPaths` supporting `AUTODORKER_DB_PATH`, `AUTODORKER_OUTPUT_DIR`, `AUTODORKER_BACKUP_DIR`, and `AUTODORKER_DORKSET_PATH`.
  - Constructs minimal `scrubbedEnv()` before invoking child binaries.
  - `runSubprocessStreamingStderr()` forwards line-by-line Rust progress into `SSEHub.BroadcastLog`.
  - `executeScanPipeline()`: Purges stale `Output/Targ*` directories, iterates validated batch targets sequentially, allocates `0700` `adk_harvest_*` temp directories, runs `dork_spider --scan --keep-harvest --json`, triggers Python Stage-2 `--verify-ast`, removes `harvestDir` (`Zero-Footprint`), invokes Python `--export-all` into `Output/TargXXX`, calls `scripts/backup_and_sign.sh`, and emits `scanUpdated` / `scanCompleted` SSE events.
- **How to modify:** Adjust per-stage timeouts (`75s` spider, `25s` Python AST, `30s` export, `15s` backup) here if auditing very slow staging environments. Keep `os.RemoveAll(harvestDir)` guaranteed on all exit paths.

#### `cmd/gateway/routes.go` (661 lines)
- **What it does:** Implements the complete HTTP/HTMX endpoint contract:
  - `GET /` — Renders `web/templates/index.html` with initial KPIs, status telemetry, SVG chart, and latest finding rows.
  - `GET /static/*` — Serves vendored CSS/JS/WOFF2 while blocking directory listings.
  - `GET /ui/input-mode?mode=single|batch` — Swaps between `input_single.html` and `input_batch.html`.
  - `POST /api/scan` — Accepts form fields `target_urls`, multipart file `src_list_file` (`.csv`/`.txt`, `<= 2 MB`), `stealth_mode`, `shadow_mode`, `local_staging`, `engagement_id`; enforces `secguard` validation (returns HTTP 400 HTMX alert on bad targets) and launches background `executeScanPipeline()`.
  - `GET /api/stream-logs-sse` — SSE streaming with ring-buffer replay (last 64 lines), 15s keep-alive heartbeats, and `connected` / `log` / `scanUpdated` / `scanCompleted` events.
  - `GET /panels/svg-telemetry` — Delegates to `python -m py_engine.cli --svg`.
  - `GET /panels/findings` — Delegates to `dork_spider --render`.
  - `GET /telemetry/status` — Delegates to `scripts/sys_telemetry.sh`.
  - `POST /api/backup` — Delegates to `scripts/backup_and_sign.sh`.
  - `GET /api/export/md/{scan_id}` & `GET /api/export/docx/{scan_id}` — Streams/generates downloadable `.md` / `.docx` deliverables using sandboxed paths and safe `Content-Disposition` filenames.
  - `GET /api/export/batch-zip` — Compiles an in-memory `archive/zip` stream of all generated artifacts under `data/Output/Targ*/`.
- **How to modify:** Preserve HTML escaping (`html.EscapeString`) on any dynamic HTML returned from Go handlers and keep `resolveSandboxedPath()` wrapping every export file read/write.

---

### 4.6 Python AST, SVG, Reporting & SBOM Engine (`CodeBase/py_engine/`)

| File | Key Functions / Classes | Purpose & How to Modify |
| :--- | :--- | :--- |
| [`py_engine/cli.py`](CodeBase/py_engine/cli.py) | `main()` | Argparse multiplexer for `--verify-ast`, `--svg`, `--export-md`, `--export-docx`, `--export-all`, `--generate-sbom`. Add new export formats here as mutually exclusive flags. |
| [`py_engine/ast_analyzer.py`](CodeBase/py_engine/ast_analyzer.py) | `calculate_shannon_entropy()`, `verify_html_dom_ast()`, `verify_js_ast_secret()`, `verify_yaml_ast()`, `verify_json_ast()`, `verify_scan_findings_in_db()` | Walks `esprima` JS AST (`VariableDeclarator`, `AssignmentExpression`, `Property`) ignoring comments cleanly, parses YAML via `yaml.SafeLoader`, validates JSON & `lxml`/`BeautifulSoup` DOM, and updates `dork_findings` / `scan_telemetry` / `surface_risk_score` inside SQLite WAL before harvest deletion. |
| [`py_engine/svg_telemetry.py`](CodeBase/py_engine/svg_telemetry.py) | `render_svg_telemetry()` | Queries SQLite WAL KPIs + severity + top-5 category hits and renders a flat orthogonal `<svg>` (`rx="0"`, `#080C12`/`#101420`/`#36A19D`/`#B85D78`/`#C9A654`/`#523B78`). Keep zero CSS classes requiring inline scripts. |
| [`py_engine/report_md.py`](CodeBase/py_engine/report_md.py) | `load_scan_report_context()`, `build_chained_impact_statement()`, `ensure_stealth_curl_poc()`, `render_markdown_report()`, `write_markdown_report()` | Generates CyberNest VIDS 5-section Markdown reports (`1. Target Overview`, `2. Methodology & Stealth Telemetry`, `3. Verified Vulnerability Breakdown` with Steps to Reproduce + Chrome 124 cURL PoC + Impact + Remediation, `4. Chained Impact Summary`, `5. Vendor/Tech Observations`). |
| [`py_engine/report_docx.py`](CodeBase/py_engine/report_docx.py) | `write_docx_report()`, `_set_cell_shading()`, `_add_mono_box()` | Generates Letter-size (`0.75"` margins) OpenXML `.docx` reports matching VIDS sections, `SYS.01` severity badge table fills (`B85D78`, `C9A654`, `36A19D`, `523B78`), dark `080C12` bordered JetBrains Mono cURL boxes, and footer DB SHA-256 verification. |
| [`py_engine/sbom_gen.py`](CodeBase/py_engine/sbom_gen.py) | `generate_sbom_manifests()` | Parses `requirements.txt`, `crates/dork_spider/Cargo.toml` + `Cargo.lock`, Go stdlib (`go1.24`), vendored `htmx.min.js` + `JetBrainsMono.woff2` (with live SHA-256 digests), and emits `SBOM.cyclonedx.json`, `SBOM.spdx.json`, and `SBOM.md`. Run `./dev.sh build` or `.venv/bin/python -m py_engine.cli --generate-sbom` after changing dependencies. |

---

### 4.7 Frontend UI (`CodeBase/web/`)

- **`web/templates/index.html` (124 lines) & `partials/input_*.html`:** Renders KPI strip (`TARGETS`, `EVALUATED`, `VERIFIED TP`, `SUPPRESSED FP`, `MAX RISK`), mode tabs (`[MODE: SINGLE URL]`, `[MODE: MULTI-URL / .CSV]`), 3 stealth/shadow/staging toggles, SSE terminal log box, export toolbar (`.MD`, `.DOCX`, `BATCH .ZIP`, `VACUUM + SHA256 LOCK`), `<svg>` container, and `#dork-findings-tbody` ledger.
- **`web/static/css/synth-ledger.css` (424 lines):** Enforces the **CyberNest Four Laws of Orthogonal Geometry**: `border-radius: 0px !important`, `box-shadow: none !important`, `backdrop-filter: none !important`, `1px` crisp borders, dark void `#080C12` / slate `#101420` / cyber cyan `#36A19D` / purple `#523B78` / magenta alert `#B85D78` / amber `#C9A654`, CRT scanline overlay (`body::after`), and `JetBrains Mono` typography (`font-variant-numeric: tabular-nums`).
- **`web/static/js/autodorker-ui.js` (116 lines):** Opens `/api/stream-logs-sse` `EventSource`, appends streamed log lines (capped at 250 DOM nodes), handles `scanUpdated`/`scanCompleted` events via `htmx.ajax` panel reloads + dynamic `/api/export/md/{id}` & `/api/export/docx/{id}` button URL updates, allows HTMX `400` validation banners to swap cleanly (`htmx:beforeSwap`), and copies `data-curl` PoCs to clipboard.

---

### 4.8 Automated Test Suites (`CodeBase/tests/` & Gateway)

| Test Suite File | Verified Scope | How to Extend / Run |
| :--- | :--- | :--- |
| [`CodeBase/tests/test_dork_ast.rs`](CodeBase/tests/test_dork_ast.rs) (266 lines) | Precedence & GHDB quirk parsing, loading & compiling all 295 `Docs/DorkSet.csv` rows (`32` chain + `263` atomic), SQLite WAL ingest roundtrip, Shannon entropy + honeypot key suppression, Dual-Gate Soft-404 SimHash + comment-stripped JS AST. | `cd CodeBase/crates/dork_spider && cargo test --locked` |
| [`CodeBase/cmd/gateway/security_test.go`](CodeBase/cmd/gateway/security_test.go) & [`CodeBase/tests/test_security_ssrf.go`](CodeBase/tests/test_security_ssrf.go) + [`ssrf_runner_test.go`](CodeBase/tests/ssrf_runner_test.go) | Loopback bind enforcement (`0.0.0.0` rejected, `127.0.0.1` accepted), multi-URL & `.csv` parsing with header skip, shell/flag injection rejection, SSRF RFC 1918/loopback/CGNAT/ULA/`169.254.169.254` blocking, path traversal & symlink escape rejection. | `cd CodeBase/cmd/gateway && go test -v ./...` and `cd CodeBase/tests && go test -v ./...` |
| [`CodeBase/tests/test_exports_e2e.py`](CodeBase/tests/test_exports_e2e.py) (417 lines) | Python `esprima`/YAML/HTML/entropy analyzers; launches an ephemeral local HTTP target serving login form, exposed directory index, commented fake JS key, placeholder YAML key, live high-entropy YAML key, Webpack chunk link, and Soft-404 catch-all; boots the real compiled `gateway` binary on an ephemeral loopback port; runs full HTTP `POST /api/scan`, SSE completion, `.MD`/`.DOCX`/Batch `.ZIP` exports, DB WAL verification, and `python-docx` parse checks. | `cd CodeBase && ./dev.sh simulate` or `.venv/bin/python -m unittest discover -s tests -p "test_*.py" -v` |

---

## 5. Deployed & Verified Functional Inventory (Current State)

Everything listed below exists in `CodeBase/` and passed full-stack verification prior to repository handoff:

1. **Full 295-Rule Boolean Dork AST Compiler:** Parses 100% of `Docs/DorkSet.csv` (`295` rules: `32` `[CHAIN]` + `263` atomic) into SQLite3 WAL `dork_catalog`.
2. **Hardened Bounded BFS Crawler + Bundler Expansion:** Respects `MAX_HTML_PAGES = 25`, `MAX_JS_FILES = 50`, `MAX_CONFIG_FILES = 50`, `MAX_ACTIVE_PROBES = 45`, parses Webpack/Vite/Rollup bundles, isolates vendor CDN telemetry, enforces `0700` + `O_NOFOLLOW` harvest safety, and enforces SSRF validation across redirects.
3. **Stealth Protocol & Baseline Resilience:** Sends Chrome 124 L7 headers, adds `250–750ms` jittered delays with max concurrency `2`, trips a WAF circuit breaker cleanly (`waf_tripped` / `HALTED_WAF`), and captures Soft-404 DOM Tag SimHash baselines.
4. **Dual-Stage AST + Shannon Entropy Engine:** Combines Rust Stage-1 Gate 0/1/2 filtering with Python Stage-2 `esprima` + `pyyaml` + `lxml`/`BeautifulSoup` AST confirmation, redacts exposed tokens before persistence, and supports Shadow Mode (`--shadow`) for low-entropy `INFO` review.
5. **Loopback FIPS-140 Go Gateway & HTMX `SYS.01` UI:** Enforces `127.0.0.1` loopback binding, strict CSP, `secguard` input/SSRF/path firewalls, scrubbed subprocess environments, real-time SSE logging, Zero-Footprint temp harvest removal, and offline vendored HTMX + JetBrains Mono assets.
6. **Multi-Target Batch Pipeline & Deliverables:** Processes single URLs, comma-separated `url1,url2,url3`, and uploaded `.csv`/`.txt` target lists sequentially into `Output/TargXXX/`, generating VIDS `.md`, pure OpenXML `.docx`, in-memory batch `.zip`, orthogonal `<svg>` telemetry charts, SHA-256 signed `VACUUM INTO` backups, and CycloneDX 1.5 / SPDX 2.3 / `SBOM.md`.
7. **Observed Verification Baseline (`./dev.sh fmt && ./dev.sh build && ./dev.sh test && ./dev.sh cli && ./dev.sh simulate`):**
   - **Rust (`cargo test --locked`):** 5/5 passed.
   - **Go (`go test -v ./...` in `cmd/gateway/` and `tests/`):** 6/6 passed (2/2 gateway, 4/4 SSRF & path sandbox).
   - **Python & Live Stack E2E (`tests.test_exports_e2e`):** 2/2 passed in ~6s, exercising Rust + Python Stage-2 AST + live Go Gateway + `.MD`/`.DOCX`/`batch-zip` exports.
   - **CLI & DB Seeding:** Ingested `295` rules (`32` chain, `263` atomic), generated `SBOM.*`, emitted live WAL status badge and SHA-256 `VACUUM INTO` snapshot.

---

## 6. Operational Commands & Environment Overrides

```bash
cd CodeBase

./dev.sh setup      # Check go/cargo/rustc/python3, build .venv, create runtime dirs
./dev.sh build      # Build Rust release + Go FIPS-140 binaries, seed DorkSet.csv, refresh SBOMs
./dev.sh test       # Execute Rust + Go + Python E2E test suites
./dev.sh cli        # Seed DB, check WAL status, run SHA-256 VACUUM INTO snapshot
./dev.sh cli <url>  # Headless CLI audit outputting JSON telemetry
./dev.sh simulate   # Run ephemeral mock HTTP + live Gateway + AST + Export E2E suite
./dev.sh run        # Launch loopback gateway at http://127.0.0.1:8090
./dev.sh fmt        # Format Rust and Go source files
```

### Supported Environment Variables
- `AUTODORKER_BIND_ADDR` — Loopback bind host:port (default `127.0.0.1:8090`, must pass `EnforceLoopbackAddress`).
- `AUTODORKER_DB_PATH` — Override SQLite3 WAL database location (default `CodeBase/data/autodorker_state.db`).
- `AUTODORKER_OUTPUT_DIR` — Override artifact staging root (default `CodeBase/data/Output`).
- `AUTODORKER_BACKUP_DIR` — Override `VACUUM INTO` snapshot directory (default `CodeBase/data/backups`).
- `AUTODORKER_DORKSET_PATH` — Override CSV rule catalog path (default `../Docs/DorkSet.csv`).

---

## 7. Prioritized TODO Roadmap (Future Improvements)

The items below are **not currently implemented** and represent recommended engineering enhancements for subsequent iterations:

### P0 — High Impact Detection & Operational Capabilities
1. **Cross-Finding & Cross-Asset `[CHAIN]` Correlator:** Extend `ast_verifier.rs` with a dedicated multi-signal correlation pass so `[CHAIN]` rules can trigger higher-confidence composite findings (e.g., correlating exposed `.git` config paths + `robots.txt` disallowed admin routes + login DOM portals or leaked Swagger endpoints on the same origin).
2. **Optional Headless Browser DOM Hydration (SPA Support):** Modern React/Vue/Next.js applications with empty server-rendered HTML currently expose routes primarily through fetched JS bundles (`extract_bundler_chunks`). Adding an optional local headless Chromium/Playwright Stage-0 DOM renderer toggle (strictly bound through Go SSRF proxy filtering) would capture client-rendered routes and runtime XHR endpoints.
3. **Interactive Scan History & Batch Switcher UI:** Expose `GET /api/scans` and a compact `SYS.01` batch/session selector dropdown in `index.html` so operators can inspect, re-export, or compare historical `scan_sessions` stored in SQLite WAL without restarting or running SQL queries manually.

### P1 — Enterprise Formats, Stealth & Windows Parity
4. **SARIF v2.1.0 & JSON-Lines Export Modes:** Add `--export-sarif` in `py_engine/cli.py` + `GET /api/export/sarif/{scan_id}` in `routes.go` to integrate AutoDorker findings seamlessly into GitHub Code Scanning, DefectDojo, or Jira pipelines.
5. **Configurable Rate Limit, Proxy & Custom Wordlist Controls in UI:** Surface `max_depth`, probe jitter range, custom HTTP proxy (with SSRF allowlist validation), and custom `DorkSet` category filters in `input_single.html` / `input_batch.html` and pass them to `dork_spider`.
6. **Pure PowerShell / Python Telemetry & Backup Parity for Windows:** `cmd/gateway/exec_bridge.go` and `routes.go` currently call `/bin/sh scripts/sys_telemetry.sh` and `scripts/backup_and_sign.sh`. Adding a Go/Python fallback path when running natively on Windows `dev.bat run` will bring full Windows dashboard `/telemetry/status` and `/api/backup` button parity without requiring WSL/Git Bash.
7. **Outbound Redirection & Custom DNS Pinning in Rust Spider:** Pin resolved DNS IPs directly into `ureq` socket connection callbacks in `spider.rs` to eliminate residual TOCTOU DNS-rebinding windows between `verify_url_ssrf()` and TCP connect.

### P2 — Performance, Packaging & CI Hardening
8. **Concurrent Bounded Batch Execution Queue with Cancelation:** Currently `executeScanPipeline()` scans batch targets sequentially inside one background goroutine and enforces no UI cancel button. Introduce a bounded worker queue (`context.WithCancel`), `/api/scan/{batch_id}/cancel`, and live `X/Y targets completed` progress bar updates.
9. **Dedicated Unit Tests Inside `secguard/` & `ast_verifier` Property Fuzzing:** Move shared tests directly into `cmd/gateway/secguard/secguard_test.go` so `go test ./...` achieves zero `[no test files]` packages, and add property-based fuzz tests (`cargo fuzz` / `proptest`) on `dork_ast::parse_dork_string()` to harden parser edge cases against arbitrary user-authored dork catalogs.
10. **Self-Contained Release Packaging (`archive/tar` + `embed.FS`):** Optionally embed `web/` templates and static assets into the Go binary via Go `embed.FS` (with live disk override in dev mode) to simplify single-folder portable deployments.
