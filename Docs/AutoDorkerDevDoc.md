# **CyberNest Labs: AutoDorker Engineering Design Document (EDD)**

* **Project Name**: `AutoDorker`

* **Author & Principal Authority**: (`Auxk0rd`), President & Chief Architect, CyberNest Holdings LLC

* **Department**: CyberNest Labs (Internal R&D & Security Software Department)

* **Target Architecture**: Local-First RPGS (Rust, Python, Go, POSIX Shell) + SQLite3 (WAL Mode) + HTMX 2.0

* **Compliance Baselines**: `CN-DIR-2026-004` (Bi-Launcher Parity), `CN-LABS-H2C-2026-01` (Loopback Sovereignty & SYS.01 Nocturnal Synth-Ledger), `CN-LABS-BRW-2026-02` (SOC Stealth & Lakehouse Archival), CMMC 2.0 L2, `GOFIPS=1` (FIPS 140-3)

## **1. Executive Summary & Architectural Philosophy**

**AutoDorker** is a local-first, autonomous Google Dorking and attack-surface verification utility designed to ingest single or comma-separated target URLs (`url1,url2,url3,...`) and dynamically audit them against the curated 295-signature `DorkSet.csv` database. Rather than relying on external search engine APIs that leak client reconnaissance telemetry to third parties or trigger immediate CAPTCHA blocks, AutoDorker translates boolean dork syntax into two deterministic local execution vectors:

1. **Local Corpus Evaluation**: Bounded Breadth-First Search (BFS) asset harvesting via a linear-time Rust spider, evaluating downloaded HTML, JavaScript, JSON, YAML, and configuration trees against compiled dork Abstract Syntax Trees (ASTs).

2. **Paced Origin Synthesis**: Translating `inurl:`, `ext:`, `filetype:`, and `intitle:"index of"` directives into low-footprint, jitter-paced HTTP probes governed by the 6-pillar SOC stealth protocol established in **BlackRoute-Web**.

To eliminate false positives common in keyword-based dork scanning, AutoDorker pairs a **Boolean Dork Query AST** and **Source Code/Document AST Parser** (inspecting HTML DOM nodes, JavaScript token streams, and YAML/JSON key-value structures) with **Shannon Entropy ($H(X)$) evaluation**. All findings are persisted to a concurrent SQLite3 Write-Ahead Logging (WAL) database and exported on demand as standardized Bug Bounty Markdown (`.md`) and Enterprise Microsoft Word (`.docx`) deliverables directly through the `SYS.01 NOCTURNAL SYNTH-LEDGER` HTMX viewport.

### **Core Architectural Invariants**

* **Strict Loopback Sovereignty (`127.0.0.1`)**: The Go Gateway binds strictly to `127.0.0.1:8090` (with dynamic fallback scan across `8000-8100`). Zero external CDNs, remote fonts, or cloud telemetry are permitted. `htmx.min.js`, `JetBrainsMono.woff2`, and `synth-ledger.css` are vendored locally inside `CodeBase/web/static/`.

* **RPGS + HTMX Division of Labor**: Go handles loopback routing, SSRF firewalling, and context-bounded subprocess multiplexing; Rust executes linear-time Thompson NFA spidering, Dork AST evaluation, Shannon entropy calculation, and zero-allocation HTMX Out-of-Band (`hx-swap-oob="true"`) emission; Python manages complex AST structural validation and `.docx` / `.md` report compilation; POSIX Shell enforces `CN-DIR-2026-004` lifecycle management, `CWE-114` PID locking, `CWE-377` symlink hardening, and atomic `VACUUM INTO` backups.

* **Orthogonal HTML-Over-The-Wire Contract**: Subprocesses emit semantic HTML fragments (`<tr>`, `<tbody>`, `<span>`, `<svg>`) coordinated via `hx-swap-oob="true"` and `HX-Trigger` headers, maintaining zero client-side JavaScript state bloat.

## **2. Target Directory Structure (`AutoDorker/`)**

This layout maps the existing workspace (`CodeBase/` and `Docs/`) into the canonical CyberNest Labs repository blueprint (`CN-LABS-H2C-2026-01`):

Plaintext

```
AutoDorker/
├── Docs/                                   # Existing Reference & Seed Documentation
│   ├── AutoDorkerOutline.md                # Core specification & operational scope
│   ├── BlackRouteWebHandoff.md             # Stealth, SSRF, & pipeline reference architecture
│   ├── DorkSet.csv                         # 295 curated dork rules (Standard & [CHAIN] tags)
│   └── How2Code_CyberNestLabsRustGoR&DGuide.md # RPGS + HTMX & SYS.01 UI engineering standard
└── CodeBase/                               # Application Implementation Root
    ├── Makefile                            # Unified build, test, fmt, and run targets
    ├── dev.sh                              # Linux POSIX Orchestrator (CN-DIR-2026-004)
    ├── dev.bat                             # Windows 10/11 Orchestrator (CN-DIR-2026-004)
    ├── launcher.sh                         # Venv manager, Rust/Go compiler & service runner
    ├── launcher.bat                        # Windows CLI parity entrypoint
    ├── requirements.txt                    # Python deps (python-docx, beautifulsoup4, lxml, pyyaml, esprima)
    ├── SBOM.cyclonedx.json                 # Signed CycloneDX 1.5 manifest
    ├── SBOM.spdx.json                      # Signed SPDX 2.3 manifest
    ├── SBOM.md                             # Human-readable dependency & SHA-256 ledger
    ├── bin/                                # Compiled polyglot binaries (chmod 550 in prod)
    │   ├── gateway                         # [Compiled Go binary] FIPS 140-3 Loopback HTTP Router
    │   └── dork_spider                     # [Compiled Rust binary] BFS Spider + Dork AST & Entropy Engine
    ├── data/
    │   ├── autodorker_state.db             # Primary SQLite3 database (WAL mode enabled)
    │   ├── migrations/
    │   │   └── 001_init_schema.sql         # Relational + ML hot/cold tables & DorkSet seed schema
    │   ├── backups/                        # Atomic VACUUM INTO snapshots + SHA-256 locks
    │   └── Output/                         # Per-target isolated artifacts (Output/Targ001 .. Output/Targ00N)
    ├── web/
    │   ├── static/
    │   │   ├── css/
    │   │   │   └── synth-ledger.css        # SYS.01 Nocturnal Synth-Ledger stylesheet (0px radius)
    │   │   ├── js/
    │   │   │   └── htmx.min.js             # Vendored HTMX 2.0 (zero external CDN)
    │   │   └── fonts/
    │   │       └── JetBrainsMono.woff2     # Vendored tabular monospace font
    │   └── templates/
    │       ├── index.html                  # Master orthogonal viewport shell
    │       └── partials/                   # HTMX fragment templates (input modes, findings, KPIs)
    ├── cmd/
    │   └── gateway/                        # [GO] Loopback HTTP Server, SSRF Guard & IPC Multiplexer
    │       ├── go.mod                      # Go 1.23+ module (zero external dependencies)
    │       ├── main.go                     # Strict 127.0.0.1 listener & CSP header enforcement
    │       ├── security.go                 # SSRF IP filter, parse_src_list & CWE-377 path sandbox
    │       ├── routes.go                   # HTMX endpoints, SSE log broadcaster & export handlers
    │       └── exec_bridge.go              # Context-bounded exec.CommandContext adapter
    ├── crates/
    │   └── dork_spider/                    # [RUST] Spider, Dork AST Parser, Entropy & HTML Emitter
    │       ├── Cargo.toml                  # Rust 2024 edition (rusqlite, regex, scraper, syn, serde)
    │       └── src/
    │           ├── main.rs                 # CLI flag dispatcher (--ingest-csv, --scan, --render)
    │           ├── dork_ast.rs             # Lexer & Recursive Descent Parser for DorkSet.csv strings
    │           ├── spider.rs               # Bounded BFS crawler, Webpack/Vite resolver & stealth pacing
    │           ├── ast_verifier.rs         # Structural HTML/JS/Config AST sink & token verifier
    │           ├── entropy.rs              # Shannon entropy H(X) calculator & false-positive filter
    │           ├── db.rs                   # rusqlite TransactionBehavior::Immediate writer
    │           └── html.rs                 # Zero-alloc HTMX + hx-swap-oob fragment generator
    ├── py_engine/                          # [PYTHON] Deep AST Triage, SVG Telemetry & Docx/MD Exporter
    │   ├── __init__.py
    │   ├── cli.py                          # Subcommand dispatcher (--verify-ast, --export-md, --export-docx)
    │   ├── ast_analyzer.py                 # Deep structural AST verification for JS/JSON/YAML/HTML
    │   ├── svg_telemetry.py                # Server-side orthogonal SVG dork category & risk charts
    │   ├── report_md.py                    # Bug Bounty Markdown (.md) generator with Stealth cURL PoCs
    │   └── report_docx.py                  # Enterprise Microsoft Word (.docx) VIDS report generator
    ├── scripts/                            # [SHELL] POSIX Telemetry, Backup & Integrity Daemons
    │   ├── sys_telemetry.sh                # 30s polled HTMX status bar (WAL state, DB size, Dork count)
    │   └── backup_and_sign.sh              # Atomic SQLite VACUUM INTO + SHA-256 state lock badge
    └── tests/
        ├── test_dork_ast.rs                # Rust unit tests for Dork lexer/parser & entropy math
        ├── test_security_ssrf.go           # Go unit tests for parse_src_list & RFC 1918 blocking
        └── test_exports_e2e.py             # Python E2E verification for .md, .docx, & batch ZIPs

```

## **3. RPGS + HTMX Polyglot Architecture & Component Specifications**

### **3.1 Data Flow & Execution Topology**

Plaintext

```
+--------------------------------------------------------------------------------------------------+
|                        USER WORKSTATION (AIR-GAPPED / 127.0.0.1 LOOPBACK)                        |
|                                                                                                  |
|  +--------------------------------------------------------------------------------------------+  |
|  | BROWSER VIEWPORT (SYS.01 Nocturnal Synth-Ledger // 0px Radius // Tabular JetBrains Mono)   |  |
|  | - Input Mode Toggle: [SINGLE URL] vs [MULTI-URL (url1,url2,url3 / .CSV)]                   |  |
|  | - Live SSE Console Stream  |  6-Cell KPI Strip  |  1-Click [.MD] [.DOCX] [BATCH .ZIP]      |  |
|  +--------------------------------------------------------------------------------------------+  |
|                 ^                                                           |                    |
|                 | Raw HTML Fragments (<tr>, <tbody>, <svg>)                 | HTTP / HTMX 2.0    |
|                 | (hx-swap-oob="true" + HX-Trigger: scanUpdated)            v (127.0.0.1:8090)   |
|  +--------------------------------------------------------------------------------------------+  |
|  | [G] GO LOOPBACK GATEWAY (cmd/gateway/ // GOFIPS=1)                                         |  |
|  | - Enforces 127.0.0.1 binding & strict local CSP                                            |  |
|  | - Sanitizes url1,url2,url3 via parseSrcList() & validates SSRF boundaries                  |  |
|  | - Multiplexes Rust, Python, and POSIX sh via scrubbed exec.CommandContext()                |  |
|  +--------------------------------------------------------------------------------------------+  |
|         |                                     |                                     |            |
|         | CLI / IPC                           | CLI / IPC                           | CLI / IPC  |
|         v                                     v                                     v            |
|  +-----------------------------+   +-------------------------------+   +----------------------+  |
|  | [R] RUST DORK SPIDER ENGINE |   | [P] PYTHON AST & DOC ENGINE   |   | [S] POSIX SHELL      |  |
|  | (crates/dork_spider)        |   | (py_engine/)                  |   | (scripts/ & dev.sh)  |  |
|  | - Parses DorkSet.csv (295)  |   | - Deep AST contextual parsing |   | - CN-DIR-2026-004    |  |
|  |   into Boolean Dork ASTs    |   |   (JS/HTML/YAML/JSON trees)   |   |   Bi-Launcher Parity |  |
|  | - Bounded BFS Crawl (25/50) |   | - Eliminates string-literal   |   | - CWE-114 PID Lock   |  |
|  |   + Stealth Jitter & WAF CB |   |   & comment false positives   |   | - CWE-377 Log Guard  |  |
|  | - Calculates H(X) Entropy   |   | - Generates Enterprise .DOCX  |   | - SQLite VACUUM INTO |  |
|  | - Emits OOB HTMX Rows       |   |   & Bug Bounty .MD reports    |   |   + SHA-256 Badge    |  |
|  +-----------------------------+   +-------------------------------+   +----------------------+  |
|         |                                     |                                     |            |
|         +-------------------------------------+-------------------------------------+            |
|                                               |                                                  |
|                                               v                                                  |
|  +--------------------------------------------------------------------------------------------+  |
|  |               LOCAL SQLITE3 BUS (WAL Mode // Foreign Keys ON // mmap 256MB)                |  |
|  |        CodeBase/data/autodorker_state.db  +  CodeBase/data/Output/Targ001..Targ00N         |  |
|  +--------------------------------------------------------------------------------------------+  |
+--------------------------------------------------------------------------------------------------+

```

### **3.2 Layer 1: `[G]` Go Loopback Gateway & Input Sanitizer (`cmd/gateway/`)**

Compiled with `GOFIPS=1` (Go 1.23+), the Go gateway acts as the air-gapped entrypoint, target input parser, SSRF firewall, and process supervisor.

1. **Strict Loopback & CSP Enforcement (`main.go`)**:

   * Verifies `ip.IsLoopback()` before binding to `127.0.0.1:8090` (scanning `8000-8100` if port `8090` is occupied).

   * Attaches immutable security headers on every response: `Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'`.

2. **Single & Multi-URL Ingestion (`security.go`)**:

   * Implements `ParseTargetInput(rawInput string, allowLocalStaging bool) ([]string, error)` to support both single URLs and comma/newline-separated lists (`url1,url2,url3,...`) or uploaded `.csv` files.

   * **Input Hardening**: Rejects shell metacharacters (`;`, `|`, `&`, `` ` ``, `$`, `(`, `)`, `<`, `>`, `\x00`), CLI flag injection (inputs starting with `-`), and path traversal tokens (`..`, `\`).

   * **Normalization & Deduplication**: Prepends `https://` if scheme is omitted, lowercases hostnames, strips URL fragments, and deduplicates targets while preserving submission order.

   * **SSRF Firewall**: Resolves host IPs via `net.LookupIP`. Rejects loopback (`127.0.0.0/8`, `::1`), RFC 1918 private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`), and cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`) unless `allowLocalStaging` is explicitly enabled by the operator (which still strictly blocks cloud metadata IPs).

3. **Scrubbed Subprocess Multiplexer (`exec_bridge.go`)**:

   * Invokes `./bin/dork_spider`, `.venv/bin/python -m py_engine.cli`, and `/bin/sh ./scripts/...` using `exec.CommandContext` with explicit argument arrays (zero `sh -c` interpolation).

   * Scrubs child process environments (`cmd.Env`), passing only `PATH`, `HOME=/tmp`, `TMPDIR`, `LANG=C.UTF-8`, and `AUTODORKER_DB_PATH` so host secrets or `LD_PRELOAD` never leak into worker processes.

### **3.3 Layer 2: `[R]` Rust Dork Spider, AST Compiler & Entropy Engine (`crates/dork_spider/`)**

The Rust engine (`dork_spider`) handles high-throughput asset crawling, `DorkSet.csv` compilation, fast structural AST pre-filtering, Shannon entropy scoring, and HTMX fragment emission.

#### **A. `DorkSet.csv` Ingestion & Boolean Dork Query AST (`dork_ast.rs`)**

`Docs/DorkSet.csv` contains **295 curated dork rules** across 13 categories (including 32 `[CHAIN]` compound rules and 263 atomic rules) covering *Files Containing Juicy Info*, *Pages Containing Login Portals*, *Files Containing Passwords*, *Vulnerable Servers*, *Various Online Devices*, *Sensitive Directories*, *Files Containing Usernames*, *Advisories and Vulnerabilities*, and *Vulnerable Files*.

Rather than executing brittle substring checks, `dork_ast.rs` tokenizes and parses every `Dork_String` into a formal **Boolean Dork Query AST**:

Rust

```
// crates/dork_spider/src/dork_ast.rs
#[derive(Debug, Clone, PartialEq)]
pub enum DorkOperator {
    InUrl(String),       // Matches normalized URL path/query segments
    InTitle(String),     // Matches HTML <title> AST node text
    InText(String),      // Matches visible text or structured config values
    FileType(String),    // Matches file extension or MIME Content-Type (ext: / filetype:)
    Site(String),        // Matches subdomain pattern (e.g., site:uat.*, site:admin.*.*)
    ExactPhrase(String), // Bare quoted string (e.g., "BEGIN OPENSSH PRIVATE KEY")
}

#[derive(Debug, Clone, PartialEq)]
pub enum DorkExpr {
    Term(DorkOperator),
    Not(Box<DorkExpr>),                  // Exclusion operator (e.g., -checkpoint.com)
    And(Vec<DorkExpr>),                  // Implicit whitespace or explicit '&' conjunction
    Or(Vec<DorkExpr>),                   // Pipe '|' disjunction inside parenthesized groups
}

pub struct CompiledDorkRule {
    pub rule_id: i64,
    pub category: String,
    pub is_chain: bool,                  // True if Category starts with "[CHAIN]"
    pub raw_dork: String,
    pub notes: String,
    pub expr_tree: DorkExpr,
    pub candidate_probe_paths: Vec<String>, // Synthesized paths for active verification
}

```

* **Local Translation of `site:` Directives**:

  * External third-party `site:` constraints (e.g., `site:github.com` in `(ext:nix | site:github.com) "BEGIN OPENSSH PRIVATE KEY"`) are evaluated locally by checking if the harvested page links to an external GitHub repository belonging to the target organization OR if any local `.nix` or config asset contains the key block.

  * Wildcard environment `site:` constraints (e.g., `site:uat.* | site:preprod.* | site:admin.*.*`) are dynamically bound to the target's root domain (`uat.<target>`, `admin.<target>`) during subdomain link discovery.

* **Candidate Path Synthesis**:

  * For rules containing `inurl:"/portal/portal.mwsl"`, `inurl:"cgi-bin/koha"`, `intitle:"index of" ("proftpd.conf" | "smb.conf")`, or `ext:env`, the AST compiler extracts deterministic relative probe candidates (only executed when `stealth_mode=False` / Active Verification Mode is enabled).

#### **B. Bounded BFS Asset Spider & Bundle Unpacker (`spider.rs`)**

* **Bounded BFS Queue**: Crawls the target starting from the root URL up to depth `2` (configurable max `3`), strictly enforcing `is_allowed_domain(url, target_domain)` so crawling never escapes to external CDNs.

* **Per-Target Caps**: Enforces `MAX_HTML_PAGES = 25` and `MAX_JS_FILES = 50` (plus discovered `.json`, `.yaml`, `.yml`, `.xml`, `.conf`, `.log`, `.txt` links), guaranteeing per-target crawl completion in `< 45 seconds`.

* **Webpack / Vite / Rollup Chunk Hydration**: Linear-time Thompson NFA regexes (`regex::RegexSet`) extract dynamic chunk manifests (`__webpack_require__.u`, `jsonpScriptSrc`, `import("./...")`, `__vitePreload`) so hidden client routes and admin portals inside split SPA bundles are harvested.

* **Isolated Sandbox Storage**: Harvested assets are written into a `0o700` temporary directory (`blackroute_dork_<hash>`) with symlink rejection (`O_NOFOLLOW`) and cleaned immediately after scan completion (Zero-Footprint Protocol).

### **3.4 Layer 3: `[P]` Python AST & Document Generation Engine (`py_engine/`)**

Python 3.12+ collaborates with the Rust spider to perform deep syntactic AST verification, flat `<svg>` visual telemetry rendering, and enterprise `.md` and `.docx` document compilation.

#### **A. Dual-Stage False-Positive Reduction: Source AST + Shannon Entropy ($H(X)$)**

Naive dork scanners flag every JavaScript bundle that happens to contain the word `"login"` in a comment, or flag documentation pages that mention `"aws_access_key_id"` with placeholder strings like `"AKIAXXXXXXXXXXXXXXXX"`. AutoDorker eliminates these false positives through a two-gate verification pipeline:

1. **Gate 1: Target Artifact AST Structural Verification (`crates/dork_spider/src/ast_verifier.rs` & `py_engine/ast_analyzer.py`)**:

   * **HTML DOM AST (`scraper` / `lxml`)**:

     * `intitle:` operators are evaluated strictly against the parsed `<head><title>` DOM node text, never raw HTML body text.

     * `intitle:"index of"` directory listing dorks verify the structural presence of directory index DOM trees (`<pre><a href="?C=N;O=D">`, Apache/Nginx/IIS parent directory `../` anchor tables) rather than merely matching the phrase in an article title.

     * Login Portal dorks (`Pages Containing Login Portals`) require structural DOM verification: the matched page must contain either an `<input type="password">` element, an `<form>` with an authentication action endpoint, or an OAuth/SAML redirect handler.

   * **JavaScript AST (`esprima` / Rust token stream)**:

     * Strips all single-line (`//`) and multi-line (`/* ... */`) comments before evaluating `intext:` or secret dorks.

     * Inspects `VariableDeclarator`, `Property` (`ObjectExpression`), and `AssignmentExpression` AST nodes. If a dork matches `"aws_access_key_id"`, the AST analyzer extracts the sibling value node assigned to that key rather than flagging a UI label or error message string.

   * **Configuration AST (`pyyaml` / `json` / `.env` key-value parser)**:

     * For YAML, JSON, and `.conf` exposures (e.g., `configmap.yaml`, `application.yml`, `proftpd.conf`), parses the file into a syntax tree and verifies that valid structural keys (`kind: ConfigMap`, `spring.datasource`, `ServerName`) exist, filtering out custom HTML Soft-404 pages that return HTTP `200 OK`.

2. **Gate 2: Shannon Entropy Calculation ($H(X)$) (`crates/dork_spider/src/entropy.rs`)**:

   * For every candidate secret, password, token, or configuration value extracted from an AST value node, AutoDorker computes the Shannon information entropy in bits per character:

     $$
     H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)
     $$

   * **Calibrated Entropy Thresholds & Suppression Rules**:

     * **Hardcoded API Keys / Cloud Tokens** (`aws_access_key_id`, `BEGIN OPENSSH PRIVATE KEY`, `AIza...`, `sk_live_...`): Enforces $H(X) \ge 3.20\text{ bits/char}$ (or $\ge 3.00$ for 20-char fixed-charset AWS keys). Dummy placeholders (`"YOUR_API_KEY_HERE"`, `"AKIAAAAAAAAAAAAAAAAA"`, `"changeme123"`, `"password"`) yield $H(X) < 2.50$ and are automatically suppressed (or downgraded to `INFO` when Shadow Mode is active).

     * **Soft-404 & Boilerplate Differential Entropy**: Compares the body Shannon entropy of probed files (`response_body_entropy`) against the target's baseline 404 page (`baseline_404_entropy` and 64-bit DOM Tag SimHash). Any response with $> 0.92$ structural SimHash similarity to the baseline 404 page is discarded as a Soft-404 false positive.

### **3.5 Layer 4: `[S]` POSIX Shell Lifecycle & Telemetry Daemons (`scripts/`, `dev.sh`)**

All shell scripts use strict `#!/bin/sh` (`set -eu`) and maintain `CN-DIR-2026-004` bi-launcher parity with Windows (`dev.bat`, `launcher.bat`):

* **`dev.sh` / `dev.bat`**: Supports `setup`, `build`, `run`, `cli`, `simulate`, `test`, and `fmt`.

* **`CWE-377` & `CWE-114` Runtime Protection**: Logs and PID locks are written strictly to `${XDG_CACHE_HOME:-$HOME/.cache}/autodorker` with `chmod 0700` and explicit `[ -L ... ]` symlink rejection.

* **`scripts/sys_telemetry.sh`**: Polled every 30s by HTMX (`#top-status-bar`), emitting WAL status, database size in KB, loaded dork count (`[DORKS: 295_ACTIVE // 32_CHAIN]`), and loopback verification (`[LOOPBACK: 127.0.0.1]`).

* **`scripts/backup_and_sign.sh`**: Executes `sqlite3 data/autodorker_state.db "VACUUM INTO 'data/backups/autodorker_snapshot_${STAMP}.db';"`, computes the `sha256sum`, and outputs the Out-of-Band `#audit-lock-badge` HTML span.

## **4. Enterprise Scanning & 6-Pillar SOC Stealth Protocol**

Directly adopting the battle-tested stealth architecture from **BlackRoute-Web** (`BlackRouteWebHandoff.md` Section 5 & Section 6), AutoDorker guarantees that dork evaluation does not trigger client WAF blocks, SIEM alert storms, or SOC IP bans:

| **Stealth Pillar** | **AutoDorker Implementation Specification** | 
| **1. Modern Browser Persona & L7 Client Hints** | All outbound HTTP requests inject the Chrome 124 on Linux persona (`User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36`) alongside full L7 Client Hints (`Sec-Ch-Ua`, `Sec-Ch-Ua-Mobile: ?0`, `Sec-Ch-Ua-Platform: "Linux"`, `Sec-Fetch-Dest: document`, `Sec-Fetch-Mode: navigate`, `Sec-Fetch-Site: none`, `Upgrade-Insecure-Requests: 1`). | 
| **2. Dual Scan Profiles (Stealth vs. Active Verification)** | **Stealth Mode (`stealth_mode=True`, Default)**: Performs bounded passive BFS spidering of linked public HTML/JS/config assets and evaluates all 295 Dork ASTs offline against the local harvest directory (zero 404 path guessing noise).  **Active Verification Mode (`stealth_mode=False`)**: Explicitly enabled for authorized engagements; synthesizes candidate URI probes from `inurl:` and `ext:` dorks. | 
| **3. Semaphore Concurrency & Jitter Pacing** | Active dork probes are bounded by a strict concurrency limit (`PROBE_CONCURRENCY_LIMIT = 2`) with randomized pre-request jitter between `250ms` and `750ms` (`PROBE_JITTER_MIN = 0.25s`, `PROBE_JITTER_MAX = 0.75s`) to break deterministic volumetric burst signatures. | 
| **4. WAF & Rate-Limit Circuit Breaker** | Evaluates every HTTP response for `429 Too Many Requests`, `503 Service Unavailable`, or `403 Forbidden` carrying WAF signatures (`cf-ray`, `cf-mitigated`, `x-amzn-waf-action`, `Server: cloudflare`, `AkamaiGHost`). Upon detection, the circuit breaker immediately halts active dork probing, cools down (`WAF_COOLDOWN_SECONDS = 5.0s`), logs a `[WARN: WAF_CIRCUIT_BREAKER_TRIPPED]` event to the SSE stream, and transitions to passive offline analysis. | 
| **5. Authorized Engagement & Akamai Staging Bypass** | When an operator supplies an `engagement_id` (e.g., `CN-AUDIT-2026-ADK`), requests inject `X-Security-Engagement: <id>` and `X-Authorized-Audit: true` (stripping CR/LF/NUL characters). Appends Akamai edge cache bypass headers (`Pragma: akamai-x-cache-on...`, `Cache-Control: no-cache`) and supports `staging:<token>` / `akamai:<token>` headers (`X-Akamai-Staging: true`, `X-Akamai-Edge-Token: <token>`). | 
| **6. Vendor Noise Exclusion & Normalized Scoring** | Third-party analytics/WAF assets (`akamai`, `tiqcdn`, `tealium`, `adobe`, `demdex`, `google-analytics`) are segregated from first-party findings. Vendor and `INFO` observations are capped at a maximum `+2` contribution to the composite Surface Risk Score (0-100 scale), preventing score saturation. | 

## **5. SQLite3 WAL Persistence Schema (`data/migrations/001_init_schema.sql`)**

Every connection initializes the database with the CyberNest Labs high-concurrency pragma block:

SQL

```
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA temp_store = MEMORY;
PRAGMA mmap_size = 268435456;
PRAGMA cache_size = -64000;
PRAGMA foreign_keys = ON;

-- 1. Curated Dork Signature Catalog (Seeded from Docs/DorkSet.csv)
CREATE TABLE IF NOT EXISTS dork_catalog (
    dork_id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    is_chain INTEGER NOT NULL DEFAULT 0 CHECK (is_chain IN (0, 1)),
    dork_string TEXT NOT NULL UNIQUE,
    compiled_ast_json TEXT NOT NULL,
    default_severity TEXT NOT NULL CHECK (default_severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    cwe_id TEXT NOT NULL,
    notes TEXT
);

-- 2. Scan Sessions (Single & Multi-Target Batch Tracking)
CREATE TABLE IF NOT EXISTS scan_sessions (
    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL,
    batch_index INTEGER NOT NULL DEFAULT 1,
    target_url TEXT NOT NULL,
    target_host_hash TEXT NOT NULL,
    scan_profile TEXT NOT NULL CHECK (scan_profile IN ('STEALTH_PASSIVE', 'ACTIVE_VERIFICATION')),
    shadow_mode INTEGER NOT NULL DEFAULT 0,
    engagement_id TEXT,
    pages_crawled INTEGER NOT NULL DEFAULT 0,
    dorks_evaluated INTEGER NOT NULL DEFAULT 295,
    surface_risk_score INTEGER NOT NULL DEFAULT 0 CHECK (surface_risk_score BETWEEN 0 AND 100),
    baseline_404_simhash TEXT,
    detected_waf_vendor TEXT DEFAULT 'NONE',
    status TEXT NOT NULL CHECK (status IN ('RUNNING', 'COMPLETED', 'HALTED_WAF', 'FAILED')),
    output_dir_rel TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- 3. Verified Dork Findings (AST + Shannon Entropy Enriched)
CREATE TABLE IF NOT EXISTS dork_findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scan_sessions(scan_id) ON DELETE CASCADE,
    dork_id INTEGER NOT NULL REFERENCES dork_catalog(dork_id),
    exact_dedup_hash TEXT NOT NULL UNIQUE,
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    cwe_id TEXT NOT NULL,
    cvss_vector TEXT NOT NULL,
    cvss_score_bps INTEGER NOT NULL, -- Stored in basis points (e.g., 750 = 7.5) for zero float drift
    matched_endpoint TEXT NOT NULL,
    ast_node_type TEXT NOT NULL,     -- e.g., 'DOM_TITLE', 'DOM_DIR_INDEX', 'JS_OBJ_PROP', 'YAML_KEY'
    ast_context_snippet TEXT NOT NULL,
    shannon_entropy_bps INTEGER NOT NULL, -- Stored in basis points (e.g., 342 = 3.42 bits/char)
    confidence_bps INTEGER NOT NULL,      -- Stored in basis points (e.g., 9500 = 95.00%)
    stealth_curl_poc TEXT NOT NULL,
    remediation TEXT NOT NULL,
    is_suppressed_fp INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON dork_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_sessions_batch_id ON scan_sessions(batch_id);

```

*Note on Numeric Determinism*: Following Pillar I (`Section 4.1`) of `How2Code_CyberNestLabsRustGoR&DGuide.md`, floating-point columns are avoided in core persistence: CVSS scores, Shannon entropy values, and confidence scores are persisted as 64-bit signed integers in basis points (`i64`, where `342` represents `3.42 bits/char` and `9500` represents `95.00%` confidence).

## **6. Enterprise Document Generation Engine (`.md` & `.docx`)**

AutoDorker provides one-click UI downloads and automated per-target directory persistence (`CodeBase/data/Output/Targ001` through `Output/Targ00N`) for both **Bug Bounty Markdown (`.md`)** and **Enterprise Microsoft Word (`.docx`)** reports, plus a consolidated **Batch ZIP Archive** (`AutoDorker_Batch_Audit_<timestamp>.zip`).

### **6.1 Standardized Report Structure (Shared Across `.md` & `.docx`)**

Every generated report contains five mandatory sections modeled on the CyberNest VIDS (Vulnerability Identification & Defense Specification) standard:

1. **Document Control & Engagement Metadata Banner**: Target URL(s), Scan ID, UTC Timestamp, Engagement ID, Scan Profile (`STEALTH_PASSIVE` vs. `ACTIVE_VERIFICATION`), Detected WAF Vendor, Surface Risk Score (`0-100`), and SHA-256 Database Audit Lock Hash.

2. **Executive Summary & Chained Dork Impact Statement**: Synthesizes how discovered `[CHAIN]` and atomic dork findings combine across the target origin (e.g., chaining an exposed `.env` / `configmap.yaml` from *Files Containing Juicy Info* with a discovered UAT portal from *\[CHAIN\] Pages Containing Login Portals*).

3. **AST & Shannon Entropy Verification Telemetry**: Summary table detailing total assets spidered, Dork AST rules triggered, Soft-404s suppressed via SimHash, and low-entropy dummy strings suppressed via $H(X)$ thresholds.

4. **Technical Findings Ledger**: Individualized cards for each verified finding containing:

   * **Category & Dork Signature**: Exact category and `Dork_String` from `DorkSet.csv`.

   * **CWE & CVSS v3.1 Classification**: Deterministic mapping (`CWE-200` Info Exposure, `CWE-538` File/Directory Exposure, `CWE-798` Hardcoded Credentials, `CWE-287` Improper Auth, `CWE-16` Configuration) with full vector string (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`).

   * **AST Structural Proof & Entropy Score**: Extracted AST node path (`ast_node_type`), redacted evidence snippet, and exact Shannon entropy score ($H(X)$ in bits/char).

   * **Stealth Browser Persona `curl` PoC**: Functional reproduction command pre-populated with Chrome 124 L7 Client Hints (`STEALTH_CURL_HEADERS_BLOCK`) so triage teams never hit edge WAF `403` blocks.

   * **Step-by-Step Reproduction & Engineering Remediation**: Concrete 3-step verification guide and remediation directives.

5. **Appendix: Segregated Vendor & Informational Observations**: Separates third-party cookies/scripts (`Akamai`, `Tealium`, `Adobe`) from actionable first-party vulnerabilities.

### **6.2 Enterprise `.docx` Specification (`py_engine/report_docx.py`)**

Built with `python-docx`, the `.docx` generator runs inside a non-blocking worker thread (`asyncio` / Go subprocess) and writes strictly inside `resolve_sandboxed_path(OUTPUT_DIR, ...)`:

* **Orthogonal Corporate Typography & Geometry**:

  * **Page Setup**: Letter (`8.5" x 11"`), `0.75"` margins on all sides, dark slate header/footer rules (`#101420`) with crisp `1pt` solid `#36A19D` borders.

  * **Body & Headings**: Clean executive typography (`Calibri` / `Liberation Sans` for prose; `JetBrains Mono` / `Courier New` `9.5pt` for Dork AST strings, AST snippets, SHA-256 hashes, and Stealth `curl` PoC blocks).

  * **Severity Badge Cells**: Table cells styled with flat cel-paint fills matching the `SYS.01` palette (`CRITICAL`/`HIGH`: `#B85D78`, `MEDIUM`: `#C9A654`, `LOW`/`OK`: `#36A19D`, `INFO`: `#523B78`).

  * **Zero Dynamic Macros or External Links**: Generates pure, self-contained OpenXML (`.docx`) documents safe for air-gapped enterprise triage environments.

## **7. `SYS.01 NOCTURNAL SYNTH-LEDGER` UI & HTMX Viewport Contract**

The browser interface (`CodeBase/web/templates/index.html`) strictly obeys the **Four Laws of Orthogonal Geometry** and **No Halation Policy** defined in `How2Code_CyberNestLabsRustGoR&DGuide.md` (`Section 7`):

* `border-radius: 0px !important; box-shadow: none !important; backdrop-filter: none !important;` globally.

* Cel-paint palette: `--bg-void: #080C12`, `--bg-panel: #101420`, `--bg-purple: #261B38`, `--border-muted: #1E2436`, `--accent-purple: #523B78`, `--accent-cyan: #36A19D`, `--text-primary: #DCD5C6`, `--text-muted: #687888`, `--status-neg: #B85D78`, `--status-warn: #C9A654`.

* Tabular monospace discipline (`font-variant-numeric: tabular-nums;`) across all metrics, entropy scores, and timestamps.

### **7.1 Orthogonal Viewport Layout**

Plaintext

```
+---------------------------------------------------------------------------------------------------+
| [SYS.01 // AUTODORKER v1.0]  [DB: WAL_OK // 412 KB] [DORKS: 295_ACTIVE] [LOOPBACK: 127.0.0.1]     |
|                              [AUDIT_LOCK: 20261112_231700 // SHA256:9f8a7b6c5d4e]                 |
+---------------------------------------------------------------------------------------------------+
| [#kpi-targets]  | [#kpi-dorks-run] | [#kpi-verified-tp] | [#kpi-ast-fp-drop] | [#kpi-risk-score]  |
|   TARGETS: 03   |   EVALUATED: 885 |   VERIFIED TP: 04  |  SUPPRESSED FP: 19 |   MAX RISK: 68/100 |
+-----------------+------------------+--------------------+--------------------+--------------------+
| LEFT COLUMN: MISSION CONTROL (420px)          | RIGHT COLUMN: VERIFIED DORK LEDGER & TELEMETRY    |
|-----------------------------------------------|---------------------------------------------------|
| [MODE: SINGLE URL] [MODE: MULTI-URL / .CSV]   | [EXPORT .MD] [EXPORT .DOCX] [DOWNLOAD BATCH .ZIP] |
|                                               |---------------------------------------------------|
| TARGET URL(S) (url1,url2,url3):               | [SERVER-SIDE FLAT <SVG> DORK CATEGORY BREAKDOWN]  |
| +-------------------------------------------+ |---------------------------------------------------|
| | https://target-a.org,https://target-b.org | | ID   | SEV  | CATEGORY        | ENTROPY | ACTIONS |
| +-------------------------------------------+ |------|------|-----------------|---------|---------|
| [x] STEALTH PROTOCOL (PASSIVE BFS + AST)      | #001 | HIGH | [CHAIN] Juicy   | 3.84 b  | [cURL]  |
| [ ] SHADOW MODE (INCLUDE LOW-ENTROPY INFO)    |      |      | configmap.yaml  | AST:OK  | [.DOCX] |
| [ ] LOCAL STAGING MODE (ALLOW RFC 1918)       | #002 | MED  | Login Portals   | N/A     | [cURL]  |
| ENGAGEMENT ID: [CN-AUDIT-2026-01            ] |      |      | inurl:login     | DOM:OK  | [.MD]   |
| [        EXECUTE AUTODORKER PIPELINE        ] |                                                   |
|-----------------------------------------------|                                                   |
| LIVE SSE TELEMETRY STREAM (/api/stream-sse)   |                                                   |
| > [18:17:01] [OK] Parsed 2 targets            |                                                   |
| > [18:17:02] [SPIDER] BFS Depth=2 (14 pages)  |                                                   |
| > [18:17:04] [AST] Dropped 7 comment matches  |                                                   |
| > [18:17:05] [ENTROPY] Dropped dummy AWS key  |                                                   |
+-----------------------------------------------+---------------------------------------------------+

```

### **7.2 HTMX Endpoint & Out-of-Band (`hx-swap-oob`) Routing Matrix**

| **HTTP Method & Route** | **Invoked RPGS Layer** | **Primary HTMX Target** | **Out-of-Band (hx-swap-oob="true") & HX-Trigger Side Effects** | 
| `GET /` | `[G]` Go Gateway | Full Viewport (`index.html`) | Loads initial KPI strip, dork catalog stats, and recent scan ledger. | 
| `GET /ui/input-mode?mode={single|batch}` | `[G]` Go Gateway | `#target-input-container` | Swaps between single URL input and multi-URL (`url1,url2,url3` + `.csv` upload) form. | 
| `POST /api/scan` | `[G]` -> `[R]` -> `[P]` -> `[S]` | `#scan-status-banner` | Starts single or multi-URL pipeline; emits `HX-Trigger: scanStarted`; streams findings via SSE and OOB updates `#dork-findings-tbody`, `#kpi-*`, and `#audit-lock-badge`. | 
| `GET /api/stream-logs-sse` | `[G]` Go SSE Hub | `#sse-console-log` | Streams real-time spider, AST filter, WAF circuit breaker, and entropy logs over `text/event-stream`. | 
| `GET /panels/svg-telemetry?scan_id={id}` | `[G]` -> `[P]` Python | `#panel-visual-telemetry` | Triggered by `HX-Trigger: scanUpdated`; returns flat server-side `<svg>` bar chart of hits vs. suppressed false positives. | 
| `GET /api/export/md/{scan_id}` | `[G]` -> `[P]` Python | Browser File Download | Streams `autodorker_triage_scan_<scan_id>.md` from `Output/Targ00N/`. | 
| `GET /api/export/docx/{scan_id}` | `[G]` -> `[P]` Python | Browser File Download | Streams `AutoDorker_Enterprise_Report_<scan_id>.docx` from `Output/Targ00N/`. | 
| `GET /api/export/batch-zip` | `[G]` Go Archive Streamer | Browser File Download | Packages all `Output/Targ001..Targ00N` (`.md` + `.docx` artifacts) into an in-memory `ZIP_DEFLATED` stream. | 
| `GET /telemetry/status` | `[G]` -> `[S]` POSIX `sh` | `#top-status-bar` | Polled every 30s (`hx-trigger="every 30s"`); invokes `scripts/sys_telemetry.sh`. | 

## **8. End-to-End Execution Pipeline (Step-by-Step Lifecycle)**

1. **Startup & Dork Catalog Initialization**:

   * Running `./dev.sh run` (or `dev.bat run`) verifies `.venv`, compiles `bin/dork_spider` (Rust) and `bin/gateway` (Go `GOFIPS=1`), runs `001_init_schema.sql`, and invokes `./bin/dork_spider --ingest-csv ../Docs/DorkSet.csv`.

   * The Rust engine parses all 295 rows from `DorkSet.csv`, compiles their Boolean Dork Query ASTs, assigns deterministic CWE and default severity mappings, and commits them to `dork_catalog` inside an `IMMEDIATE` WAL transaction.

2. **Target Ingestion & SSRF Validation**:

   * The operator submits either a single URL (`[https://portal.example.com](https://portal.example.com)`) or a comma-separated list (`[https://app1.example.com](https://app1.example.com),[https://app2.example.com](https://app2.example.com),[https://uat.example.com](https://uat.example.com)`).

   * Go's `ParseTargetInput()` sanitizes each entry, strips shell/path injection tokens, deduplicates hosts, and verifies DNS resolution against the SSRF blocklist.

   * Stale `CodeBase/data/Output/Targ*` directories from prior runs are purged, and fresh sandboxed directories (`Output/Targ001 .. Output/Targ00N`) are provisioned.

3. **Sequential Target Auditing (`[1/N .. N/N]`)**:

   * For each target `i` in `1..N`:

     * **Phase 1 (Baseline & WAF Profiling)**: Sends 3 benign requests with Chrome 124 L7 Client Hints to record `baseline_latency_mean_ms`, `baseline_404_simhash` (64-bit DOM Tag SimHash), and initial WAF vendor fingerprints.

     * **Phase 2 (Bounded BFS Spidering)**: `bin/dork_spider` crawls the target up to depth `2` (`MAX_HTML_PAGES = 25`, `MAX_JS_FILES = 50`), resolving Webpack/Vite/Rollup dynamic chunks into a `0o700` temporary harvest directory.

     * **Phase 3 (Paced Active Dork Probing - Optional)**: If `stealth_mode=False`, `bin/dork_spider` executes jitter-paced (`250ms-750ms`, concurrency `2`) requests for candidate paths derived from `DorkSet.csv`, monitored continuously by the WAF circuit breaker.

     * **Phase 4 (Dork AST Evaluation + Target AST Verification + Shannon Entropy)**:

       * Evaluates all 295 compiled Dork ASTs against harvested files and headers.

       * Candidate matches pass through **Gate 1 (Source AST Verification)** (confirming `<title>`, directory index DOM structures, login form elements, or uncommented JS/YAML/JSON key-value nodes) and **Gate 2 (Shannon Entropy $H(X)$)** (enforcing $H(X) \ge 3.20\text{ bits/char}$ on secrets and filtering Soft-404s via SimHash).

     * **Phase 5 (ACID Persistence & OOB UI Emission)**:

       * Verified findings and synthesized Stealth `curl` PoCs are written to `autodorker_state.db` (`dork_findings`).

       * Rust emits the `<tr>` rows and `hx-swap-oob="true"` KPI counters directly to the UI.

     * **Phase 6 (Per-Target `.md` & `.docx` Artifact Generation)**:

       * Invokes `py_engine/cli.py --export-all --scan-id <id> --out-dir data/Output/Targ00i`, generating `autodorker_triage_scan_<id>.md` and `AutoDorker_Enterprise_Report_<id>.docx`.

     * **Phase 7 (Zero-Footprint Cleanup & Atomic Backup)**:

       * Removes the temporary `0o700` asset harvest folder and executes `scripts/backup_and_sign.sh` to lock the SQLite WAL snapshot with a SHA-256 badge.

## **9. Universal Command Parity (`CN-DIR-2026-004`) & Verification Matrix**

Both `CodeBase/dev.sh` (POSIX `/bin/sh`) and `CodeBase/dev.bat` (Windows 10/11) implement the exact command contract required by `How2Code_CyberNestLabsRustGoR&DGuide.md`:

| **Subcommand** | **Linux (./dev.sh <cmd>)** | **Windows (dev.bat <cmd>)** | **Operational Function** | 
| **`setup`** | `./dev.sh setup` | `dev.bat setup` | Verifies `go`, `cargo`, `python3`, `sqlite3`; initializes `.venv`; installs `requirements.txt` (`python-docx`, `lxml`, `pyyaml`, `esprima`). | 
| **`build`** | `./dev.sh build` | `dev.bat build` | Compiles `bin/dork_spider` (`cargo build --release`) and `bin/gateway` (`GOFIPS=1 go build -ldflags="-s -w"`), seeds `DorkSet.csv`, and updates SBOMs. | 
| **`run` / `serve`** | `./dev.sh run` | `dev.bat run` | Launches the loopback gateway on `127.0.0.1:8090` with `CWE-114` PID tracking and `CWE-377` log hardening. | 
| **`cli`** | `./dev.sh cli` | `dev.bat cli` | Executes a deterministic headless CLI dork audit against a target URL or comma list and verifies CMMC 2.0 L2 compliance. | 
| **`simulate`** | `./dev.sh simulate` | `dev.bat simulate` | Spins up an ephemeral local mock HTTP server with synthetic dork exposures + low-entropy honeypot strings, runs a batch scan, and verifies `0` false positives and valid `.md`/`.docx` generation. | 
| **`test`** | `./dev.sh test` | `dev.bat test` | Executes `cargo test` (Dork AST + entropy), `go test ./...` (SSRF + input parser), and `python3 -m unittest` (`.docx`/`.md` exports) inside isolated temp sandboxes. | 
| **`fmt`** | `./dev.sh fmt` | `dev.bat fmt` | Formats Rust (`cargo fmt`) and Go (`go fmt ./...`) source trees. | 
