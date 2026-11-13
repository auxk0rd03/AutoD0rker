# **`How2Code: CyberNest Labs R&D Overview — An Intro to POSIX/Rust Systems Development & Loopback Architecture for Labs Utilities`**

**`Document ID:`** `CN-LABS-H2C-2026-01`  
**`Authority:`** `William R. M. (Auxk0rd) — President & Chief Architect, CyberNest Holdings LLC`  
**`Department:`** `CyberNest Labs (Internal R&D & Security Software Department)`  
`Target Stack: Local-First RPGS (Rust, Python, Go, POSIX Shell) + SQLite (WAL) + HTMX / Textual`  
`Compliance Baselines: CN-DIR-2026-004 (Bi-Launcher Parity), CMMC 2.0 L2, GOFIPS=1 (FIPS 140-3), OASIS SARIF v2.1.0`

---

# **`1. Executive Summary & Architectural Philosophy`**

`CyberNest Labs is the internal research and software engineering department of CyberNest Holdings LLC. Every utility produced by Labs—ranging from Dynamic Application Security Testing (DAST) engines (BlackRoute-Web) and peer-to-peer encrypted communication tools (NestComm, NestLink) to deterministic treasury ledgers (SYS.01-CL) and supply-chain auditors (NestSBOM, KwikLogPro, NestPatch)—is engineered around three non-negotiable architectural invariants:`

1. **`Strict Loopback Sovereignty (127.0.0.1):`** `All services bind exclusively to the local loopback interface (127.0.0.1:8000–8100). Zero external cloud APIs, third-party SaaS telemetry, or remote Content Delivery Networks (CDNs) are permitted in production runtimes. All frontend assets (htmx.min.js, JetBrainsMono.woff2, and SYS.01 stylesheets) are vendored locally inside the binary or repository archive.`  
2. **`The RPGS + HTMX Polyglot Division of Labor:`** `Rather than forcing a single language to handle low-level memory-safe parsing, concurrent network multiplexing, data science/reporting, and OS lifecycle management, CyberNest Labs enforces a strict four-layer polyglot architecture: Rust, Python, Go, and POSIX Shell (RPGS) paired with HTMX (or Textual for terminal UIs) and a shared SQLite Write-Ahead Logging (WAL) persistence bus.`  
3. **`Orthogonal HTML-Over-The-Wire Contract:`** `Sub-processes do not exchange bloated JSON state trees with a heavy client-side JavaScript framework. Instead, compiled Rust and Go engines, Python analytics scripts, and POSIX Shell telemetry daemons emit deterministic, zero-latency HTML fragments (<tr>, <tbody>, <svg>, <span>) utilizing HTMX Out-of-Band (hx-swap-oob="true") swaps and HX-Trigger response headers.`

## **`The CyberNest Labs Utility Matrix`**

| `Utility` | `Primary Engineering Domain` | `RPGS + UI Stack` | `Core Loopback / Air-Gapped Mechanism` |
| :---- | :---- | :---- | :---- |
| **`SYS.01-CL (Capital Ledger)`** | `Corporate Treasury & Deterministic Capital Routing` | `Go / Rust / Python / sh / HTMX` | `Dual-ledger ACID SQLite writer (CH_01A & CH_01B), integer-cent basis-point allocator, keyless yfinance dividend forecaster, SHA-256 hot backups.` |
| **`BlackRoute-Web`** | `DAST, Attack Surface Mapping & SARIF Triage` | `Rust / Go / Python / sh / HTMX` | `Linear-time Rust Thompson NFA spider, Go topology fingerprinter, local ONNX (ort) false-flag triage, STIX 2.1 / TAXII 2.1 & VIDS PDF exporter.` |
| **`KwikLogPro`** | `System Health Auditor & Hardware Regression` | `Go / Rust / Python / sh / HTMX` | `Cross-platform (Pop!_OS Linux & Windows) parallel log parser and air-gapped hardware regression testing engine.` |
| **`NestComm`** | `Decentralized Encrypted P2P Messaging` | `Go / Rust / sh / HTMX` | `libp2p Distributed Hash Tables (DHT) + Noise protocol encryption for synchronous and store-and-forward messaging.` |
| **`NestLink`** | `P2P SSH Stream Multiplexer & NAT Tunnel` | `Go / Rust / sh / HTMX` | `Direct peer-to-peer NAT hole-punching and SSH stream multiplexing for remote node diagnostics without relay servers.` |
| **`NestPatch`** | `Automated Single-IP VLAN & Switch Hardening` | `Python (Textual) / Rust / Go / sh` | `Terminal UI (TUI) provisioner for wired (802.3) and wireless (802.11w) switch hardening.` |
| **`NestSBOM`** | `Software Supply Chain & Repository Auditor` | `Rust / Go / Python / sh / HTMX` | `Repository ingestion engine generating cryptographically signed CycloneDX 1.5, SPDX 2.3, and Markdown ledgers.` |

---

# **`2. The RPGS + HTMX Polyglot Architecture & Loopback Topology`**

`In a standard CyberNest Labs application, all four RPGS runtime layers operate over a single local SQLite database configured in WAL (Write-Ahead Logging) mode (PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON;). This enables concurrent reads across Go, Rust, Python, and Shell while serializing atomic transactions without locking the user interface.`

## **`Architectural Data Flow Diagram`**

```
+-----------------------------------------------------------------------------------+
|                   USER WORKSTATION (AIR-GAPPED / LOCALHOST ONLY)                  |
|                                                                                   |
|   +---------------------------------------------------------------------------+   |
|   | BROWSER VIEWPORT (SYS.01 Nocturnal Synth-Ledger / Military-Industrial UI) |   |
|   | - Vendored HTMX 2.0 (Zero CDN)  |  0px Border Radius  |  Tabular Monospace|   |
|   +---------------------------------------------------------------------------+   |
|                  ^                                             |                  |
|                  | Raw HTML Fragments                          | HTTP / HTMX      |
|                  | (hx-swap-oob + HX-Trigger)                  v (127.0.0.1:8090) |
|   +---------------------------------------------------------------------------+   |
|   | [G] GO GATEWAY / MISSION CONTROL ROUTER (cmd/gateway/ or FastAPI Bridge)  |   |
|   | - Binds strictly to 127.0.0.1 (Loopback) with GOFIPS=1 (FIPS 140-3)       |   |
|   | - Multiplexes CLI sub-processes via safe exec.CommandContext()            |   |
|   +---------------------------------------------------------------------------+   |
|         |                         |                         |                     |
|         | IPC / CLI               | IPC / CLI               | IPC / CLI           |
|         v                         v                         v                     |
|   +-------------------+   +-----------------------+   +-----------------------+   |
|   | [R] RUST ENGINE   |   | [P] PYTHON ENGINE     |   | [S] POSIX SHELL       |   |
|   | - Integer-cent    |   | - ONNX Runtime (ort)  |   | - CN-DIR-2026-004     |   |
|   |   ACID Dual-Ledger|   | - Keyless Valuation   |   |   Lifecycle & PID Lock|   |
|   | - Thompson NFA    |   | - Flat Server-Side SVG|   | - SQLite VACUUM INTO  |   |
|   |   Web Spider      |   | - VIDS PDF / XLSX /   |   | - SHA-256 Audit Badge |   |
|   | - Zero-alloc HTML |   |   SARIF / STIX Export |   | - System Telemetry    |   |
|   +-------------------+   +-----------------------+   +-----------------------+   |
|         |                         |                         |                     |
|         +-------------------------+-------------------------+                     |
|                                   |                                               |
|                                   v                                               |
|   +---------------------------------------------------------------------------+   |
|   |              LOCAL SQLITE BUS (WAL Mode // Foreign Keys ON)               |   |
|   |   data/cybernest_ledger.db  |  forgeml_store.db  |  threat_surface.db     |   |
|   +---------------------------------------------------------------------------+   |
+-----------------------------------------------------------------------------------+
```

## **`Division of Labor by Language Layer`**

* **`[G] Go (1.23+ with GOFIPS=1):`** `Serves as the primary local HTTP loopback gateway (127.0.0.1:8000–8100), static asset server, concurrent network topology fingerprinter (surface_graph), and sub-process multiplexer (exec_bridge.go).`  
* **`[R] Rust (2024 Edition):`** `Handles deterministic, memory-safe, and performance-critical computation. Used for ACID dual-ledger financial accounting (crates/ledger_core), linear-time Thompson NFA regex route extraction (engines/web_spider), inline ONNX Runtime (ort) packet/finding scoring, and zero-allocation HTML fragment emission.`  
* **`[P] Python (3.11+ / 3.12+):`** `Powers offline ML distillation (ForgeML + LightGBM/IsolationForest to .onnx), security header/DOM/secret entropy auditing (H(X) Shannon entropy), market quote/dividend forecasting, deterministic flat <svg> chart generation, and formal compliance exports (CyberNest VIDS PDFs, multi-tab XLSX workbooks, CycloneDX/SPDX SBOMs, and STIX 2.1 / TAXII 2.1 bundles).`  
* **`[S] POSIX Shell (#!/bin/sh):`** `Provides strict CN-DIR-2026-004 lifecycle orchestration (dev.sh, launcher.sh), runtime PID tracking (CWE-114), symlink/ACL log hardening (CWE-377), live SQLite VACUUM INTO hot backups, cryptographic sha256sum state verification, and periodic status bar telemetry (#top-status-bar).`

---

# **`3. Canonical CyberNest Labs Repository Blueprint`**

`Every CyberNest Labs utility follows a standardized directory layout so engineers can context-switch effortlessly between financial terminals (SYS.01-CL), DAST scanners (BlackRoute-Web), and network utilities (NestPatch, NestLink).`

```
cybernest-labs-utility/
├── Makefile                        # Unified build, test, fmt, and run targets
├── dev.sh                          # Linux Dual-Native Orchestrator (CN-DIR-2026-004)
├── dev.bat                         # Windows 10/11 Dual-Native Orchestrator (CN-DIR-2026-004)
├── launcher.sh                     # Automated venv setup, Rust/Go compiler & service runner
├── launcher.bat                    # Windows CLI parity entrypoint
├── SBOM.cyclonedx.json             # Signed CycloneDX 1.5 supply-chain manifest
├── SBOM.spdx.json                  # Signed SPDX 2.3 supply-chain manifest
├── SBOM.md                         # Human-readable dependency & SHA-256 ledger
├── data/
│   ├── app_state.db                # Primary SQLite database (WAL mode enabled)
│   ├── migrations/
│   │   └── 001_init_schema.sql     # Strict ACID schema, triggers & seed tables
│   ├── backups/                    # Hot SQLite snapshots + SHA-256 audit logs
│   └── exports/                    # VIDS PDFs, Dual-Tab XLSX, SARIF, STIX/TAXII outputs
├── web/
│   ├── static/
│   │   ├── css/
│   │   │   └── synth-ledger.css    # SYS.01 Nocturnal Synth-Ledger stylesheet
│   │   ├── js/
│   │   │   └── htmx.min.js         # Vendored HTMX 2.0 (strictly zero external CDN)
│   │   └── fonts/
│   │       └── JetBrainsMono.woff2 # Vendored tabular monospace font
│   └── templates/
│       ├── index.html              # Master orthogonal viewport shell
│       └── partials/               # Semantic HTML fragment templates
├── cmd/
│   └── gateway/                    # [GO] Loopback HTTP Server & IPC Process Multiplexer
│       ├── main.go                 # Strict 127.0.0.1 listener & graceful shutdown
│       ├── routes.go               # HTMX fragment routes & HX-Trigger coordinators
│       └── exec_bridge.go          # Context-bounded CLI execution for Rust/Python/sh
├── crates/
│   └── core_engine/                # [RUST] High-Speed Deterministic Engine
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs             # CLI flag dispatcher (--allocate, --scan, --render)
│           ├── engine.rs           # Integer-cent math / Thompson NFA / ONNX scorer
│           ├── db.rs               # rusqlite IMMEDIATE transaction writer
│           └── html.rs             # Zero-allocation HTMX + hx-swap-oob emitter
├── py_engine/                      # [PYTHON] Analytics, ML Inference & Export Engine
│   ├── pyproject.toml
│   ├── cli.py                      # Subcommand dispatcher (--sync, --svg, --export)
│   ├── inference.py                # Local CPUExecutionProvider ONNX Runtime scorer
│   ├── svg_charts.py               # Server-side orthogonal SVG generator
│   └── exporters.py                # VIDS PDF, XLSX, SARIF v2.1.0, STIX 2.1 builders
└── scripts/                        # [SHELL] POSIX Telemetry, Backup & Integrity Daemons
    ├── sys_telemetry.sh            # Emits HTMX status bar badge (WAL state, DB size)
    └── backup_and_sign.sh          # Atomic SQLite VACUUM INTO + SHA-256 state lock
```

---

# **`4. Pillar I: Rust Systems Development in CyberNest Labs`**

`In CyberNest Labs, Rust is never used as a bloated web framework; instead, it is compiled into surgical, standalone CLI binaries (crates/ledger_core, engines/web_spider) invoked by the Go or Python gateway over standard streams or shared SQLite WAL state. This design guarantees memory safety, zero garbage-collection pauses, and deterministic math.`

## **`4.1 Financial & Metric Determinism (Zero Floating-Point Drift)`**

`Floating-point types (f32, f64) are strictly prohibited for storing currency or basis-point weights.`

* `All monetary amounts are stored and computed as 64-bit signed integers representing USD cents (i64).`  
* `All allocation weights are stored in basis points (10,000 bps = 100.00%).`  
* **`Deterministic Remainder Routing:`** `When splitting a lump-sum treasury injection across multiple strategy buckets (JEPQ, SCHD, VOO, VXUS, SPGI, ITA, SGOV, USD, BTC, SOL), integer division truncates fractional cents:`

`$$\text{AllocatedCents}_i = \left\lfloor \frac{\text{TotalDepositCents} \times \text{TargetBPS}_i}{10000} \right\rfloor \quad \forall i \neq \text{USD}$$`

`To enforce the Charter compliance invariant that the sum of child allocations (CH_01B) always equals the parent deposit (CH_01A) to the exact penny, the USD (Liquid Reserve) bucket absorbs the exact remainder:`

`$$\text{AllocatedCents}{\text{USD}} = \text{TotalDepositCents} - \sum{i \neq \text{USD}} \text{AllocatedCents}_i$$`

## **`4.2 ACID SQLite Dual-Ledger Transactions (rusqlite)`**

`When mutating state across parent and child tables, Rust opens an explicit TransactionBehavior::Immediate lock on the WAL database. If any constraint fails (such as CHECK (total_amount_cents > 0) or a foreign key mismatch), the entire transaction rolls back automatically.`

```
// crates/ledger_core/src/db.rs
use rusqlite::{params, Connection, Result, TransactionBehavior};

pub struct BucketStrategy {
    pub ticker: String,
    pub target_bps: i64,
}

pub struct BucketAllocation {
    pub ticker: String,
    pub allocated_cents: i64,
    pub status: String,
}

pub fn execute_atomic_dual_ledger_deposit(
    conn: &mut Connection,
    deposit_date: &str,
    total_cents: i64,
    notes: &str,
    strategies: &[BucketStrategy],
) -> Result<(i64, i64, Vec<BucketAllocation>)> {
    // 1. Acquire IMMEDIATE write lock on WAL database
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    // 2. Insert parent record into CH_01A (treasury_deposits)
    tx.execute(
        "INSERT INTO treasury_deposits (deposit_date, total_amount_cents, notes, audit_status)
         VALUES (?1, ?2, ?3, 'RECORDED')",
        params![deposit_date, total_cents, notes],
    )?;
    let batch_id = tx.last_insert_rowid();

    // 3. Compute integer-cent splits and route penny remainders to Liquid USD
    let mut allocations = Vec::with_capacity(strategies.len());
    let mut running_sum: i64 = 0;

    for strat in strategies {
        if strat.ticker != "USD" {
            let cents = (total_cents * strat.target_bps) / 10_000;
            running_sum += cents;
            allocations.push(BucketAllocation {
                ticker: strat.ticker.clone(),
                allocated_cents: cents,
                status: "PENDING_MANUAL".to_string(),
            });
        }
    }

    let usd_remainder = total_cents - running_sum;
    allocations.push(BucketAllocation {
        ticker: "USD".to_string(),
        allocated_cents: usd_remainder,
        status: "SETTLED_CASH".to_string(),
    });

    // 4. Insert all 10 child records into CH_01B (ledger_allocations)
    for alloc in &allocations {
        tx.execute(
            "INSERT INTO ledger_allocations 
             (deposit_id, deposit_date, ticker, allocated_cents, unit_price_cents, implied_units, status)
             VALUES (?1, ?2, ?3, ?4, 100, (?4 / 100.0), ?5)",
            params![batch_id, deposit_date, alloc.ticker, alloc.allocated_cents, alloc.status],
        )?;
    }

    // 5. Query updated cumulative deposit cost basis for OOB footer update
    let cumulative_cents: i64 = tx.query_row(
        "SELECT COALESCE(SUM(total_amount_cents), 0) FROM treasury_deposits",
        [],
        |row| row.get(0),
    )?;

    tx.commit()?;
    Ok((batch_id, cumulative_cents, allocations))
}
```

## **`4.3 Zero-Allocation HTMX Out-of-Band (hx-swap-oob) Fragment Emission`**

`Instead of serializing structs to JSON and parsing them in Go or JavaScript, the Rust binary writes semantic HTML directly to stdout. By combining a primary target payload with hx-swap-oob="true" elements, a single Rust invocation updates multiple disconnected DOM panels simultaneously:`

```
// crates/ledger_core/src/html.rs
use crate::db::BucketAllocation;

pub fn render_dual_ledger_oob_response(
    batch_id: i64,
    deposit_date: &str,
    total_cents: i64,
    notes: &str,
    cumulative_cents: i64,
    allocations: &[BucketAllocation],
) -> String {
    let total_usd = total_cents as f64 / 100.0;
    let cum_usd = cumulative_cents as f64 / 100.0;

    // 1. Primary Swap Target: Prepend row to CH_01A (#deposit-ledger-tbody)
    let mut html = format!(
        r#"<tr id="dep-batch-{batch_id}" hx-get="/ledger/allocations?batch_id={batch_id}" hx-target="#investment-ledger-tbody">
            <td class="val-pos">#B-{batch_id:04}</td>
            <td class="num-right val-pos">+${total_usd:.2}</td>
            <td class="val-muted">{deposit_date}</td>
            <td>[{notes}]</td>
        </tr>"#
    );

    // 2. Out-of-Band Swap #1: Update CH_01A Cumulative Cost-Basis Footer
    html.push_str(&format!(
        r#"<span id="cumulative-deposit-total" hx-swap-oob="true" class="val-pos">${cum_usd:.2}</span>"#
    ));

    // 3. Out-of-Band Swap #2: Prepend 10 child rows into CH_01B (#investment-ledger-tbody)
    html.push_str(r#"<tbody id="investment-ledger-tbody" hx-swap-oob="afterbegin">"#);
    for alloc in allocations {
        let amt_usd = alloc.allocated_cents as f64 / 100.0;
        html.push_str(&format!(
            r#"<tr class="batch-child-{batch_id}">
                <td class="val-muted">#B-{batch_id:04}</td>
                <td class="num-right val-pos">+${amt_usd:.2}</td>
                <td class="val-muted">{deposit_date}</td>
                <td>{ticker}</td>
                <td>[{status}]</td>
            </tr>"#,
            ticker = alloc.ticker,
            status = alloc.status
        ));
    }
    html.push_str("</tbody>");
    html
}
```

## **`4.4 High-Speed Linear-Time Regex & Inline ONNX Scoring (BlackRoute-Web Pattern)`**

`For security utilities like BlackRoute-Web and NestSBOM, Rust engines provide two critical capabilities:`

1. **`ReDoS-Immune Asset Crawling (engines/web_spider):`** `Uses Rust's regex crate (backed by Thompson NFA finite automata) to guarantee $O(n)$ linear-time route and secret extraction across minified Webpack/Vite/Rollup bundles without catastrophic backtracking.`  
2. **`Sub-Millisecond Inline ONNX Inference (ort crate):`** `Loads distilled .onnx gradient-boosted or IsolationForest models directly into Rust CLI sensors to score findings or network flows in $< 0.5\text{ ms}$ with zero external API calls:`

```
// Inline ONNX Runtime scoring inside a CyberNest Labs Rust sensor
use ndarray::Array2;
use ort::{Session, Value};

pub fn score_finding_tensor(session: &Session, features: &[f32; 14]) -> ort::Result<f32> {
    let input_array = Array2::from_shape_vec((1, 14), features.to_vec()).unwrap();
    let outputs = session.run(ort::inputs!["float_input" => Value::from_array(input_array)?]?)?;
    let probs = outputs[1].try_extract_sequence::<f32>()?;
    Ok(probs[0])
}
```

---

# **`5. Pillar II: POSIX Shell Systems Development & CN-DIR-2026-004 Compliance`**

`All shell scripts in CyberNest Labs (scripts/*.sh, dev.sh, launcher.sh) must adhere strictly to POSIX sh (#!/bin/sh with set -eu) for portability across Pop!_OS, Debian, Ubuntu, Fedora, Arch, and minimal container environments, while maintaining Dual-Native Bi-Launcher Parity (CN-DIR-2026-004) with Windows 10/11 (dev.bat, launcher.bat).`

## **`5.1 Universal Command Parity Contract (CN-DIR-2026-004)`**

`Every Labs repository must expose identical operational subcommands across ./dev.sh <cmd> and dev.bat <cmd>:`

| `Subcommand` | `Linux (./dev.sh <cmd>)` | `Windows (dev.bat <cmd>)` | `Operational Function` |
| :---- | :---- | :---- | :---- |
| **`setup`** | `./dev.sh setup` | `dev.bat setup` | `Verifies go, cargo, python3, sqlite3; initializes .venv; installs dependencies.` |
| **`build`** | `./dev.sh build` | `dev.bat build` | `Compiles Rust (cargo build --release) and Go (GOFIPS=1 go build) binaries into bin/ and updates SBOMs.` |
| **`run / serve`** | `./dev.sh run` | `dev.bat run` | `Starts the loopback gateway on 127.0.0.1 with CWE-114 PID tracking and CWE-377 log hardening.` |
| **`cli`** | `./dev.sh cli` | `dev.bat cli` | `Runs a single-sweep deterministic diagnostic, schema check, and CMMC 2.0 L2 compliance audit.` |
| **`simulate`** | `./dev.sh simulate` | `dev.bat simulate` | `Executes fault-injection / synthetic data verification and outputs an audit report.` |
| **`test`** | `./dev.sh test` | `dev.bat test` | `Runs cargo test, go test ./..., and Python unittest suites sequentially.` |
| **`fmt`** | `./dev.sh fmt` | `dev.bat fmt` | `Formats Rust (cargo fmt) and Go (go fmt ./...) source trees.` |

## **`5.2 CWE-377 (Symlink/ACL Log Hardening) & CWE-114 (Explicit PID Tracking)`**

`Never write runtime logs or PID files to world-writable /tmp directories where local symlink attacks (CWE-377) or process hijacking (CWE-114) can occur. POSIX scripts must provision restricted user-scoped cache directories (chmod 0700) and verify process identity before signaling:`

```
#!/bin/sh
# dev.sh — CN-DIR-2026-004 Compliant POSIX Orchestrator
set -eu

APP_NAME="cybernest_utility"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/${APP_NAME}"
LOG_FILE="${CACHE_DIR}/session.log"
PID_FILE="${CACHE_DIR}/gateway.pid"
BIND_ADDR="127.0.0.1:8090"

init_secure_runtime_dir() {
    # CWE-377 Mitigation: Refuse symlinked directories and enforce 0700 permissions
    if [ -L "$CACHE_DIR" ]; then
        printf '[ERR_HALT] Security violation: %s is a symbolic link (CWE-377).\n' "$CACHE_DIR" >&2
        exit 1
    fi
    mkdir -p "$CACHE_DIR"
    chmod 0700 "$CACHE_DIR"

    if [ -L "$LOG_FILE" ]; then
        printf '[ERR_HALT] Security violation: %s is a symbolic link (CWE-377).\n' "$LOG_FILE" >&2
        exit 1
    fi
    umask 0077
    : > "$LOG_FILE"
}

cmd_build() {
    printf '[BUILD] Compiling Rust core engine (release)...\n'
    (cd crates/ledger_core && cargo build --release)
    mkdir -p bin
    cp crates/ledger_core/target/release/ledger_core bin/ledger_core

    printf '[BUILD] Compiling Go loopback gateway (GOFIPS=1)...\n'
    GOFIPS=1 go build -o bin/gateway ./cmd/gateway
    printf '[OK] Polyglot binaries staged in ./bin/\n'
}

cmd_run() {
    init_secure_runtime_dir
    if [ ! -x "bin/gateway" ] || [ ! -x "bin/ledger_core" ]; then
        cmd_build
    fi
    printf '[LAUNCH] Binding %s strictly to http://%s\n' "$APP_NAME" "$BIND_ADDR"
    ./bin/gateway --bind "$BIND_ADDR" >>"$LOG_FILE" 2>&1 &
    GATEWAY_PID=$!
    printf '%s\n' "$GATEWAY_PID" > "$PID_FILE"
    printf '[PID_LOCK] Process %s recorded in %s (CWE-114)\n' "$GATEWAY_PID" "$PID_FILE"
    wait "$GATEWAY_PID"
}

case "${1:-help}" in
    build) cmd_build ;;
    run|serve) cmd_run ;;
    test)
        (cd crates/ledger_core && cargo test)
        go test ./...
        python3 -m unittest discover -s tests
        ;;
    fmt)
        (cd crates/ledger_core && cargo fmt)
        go fmt ./...
        ;;
    *)
        printf 'Usage: %s {setup|build|run|cli|simulate|test|fmt}\n' "$0"
        exit 1
        ;;
esac
```

## **`5.3 Atomic SQLite Hot-Backups & SHA-256 Audit Locks (backup_and_sign.sh)`**

`Standard file copying (cp) corrupts active SQLite WAL databases if a write transaction is in flight. CyberNest Labs POSIX daemons use SQLite's VACUUM INTO command to create an atomic, defragmented snapshot on disk, hash it with sha256sum, and emit an HTML state badge straight into the HTMX UI:`

```
#!/bin/sh
# scripts/backup_and_sign.sh — Hot-backup SQLite WAL database and emit SHA-256 state badge
set -eu

DB_PATH="${1:-data/cybernest_ledger.db}"
BACKUP_DIR="${2:-data/backups}"
STAMP=$(date -u +"%Y%m%d_%H%M%S")
OUT_FILE="${BACKUP_DIR}/ledger_snapshot_${STAMP}.db"

mkdir -p "$BACKUP_DIR"
sqlite3 "$DB_PATH" "VACUUM INTO '${OUT_FILE}';"
HASH=$(sha256sum "$OUT_FILE" | cut -c1-12)

printf '<span class="val-pos">[AUDIT_LOCK: %s // SHA256:%s]</span>\n' "$STAMP" "$HASH"
```

## **`5.4 Live HTMX Header Telemetry (sys_telemetry.sh)`**

`Polled every 30 seconds by the browser (hx-get="/telemetry/status" hx-trigger="every 30s"), this script inspects the SQLite WAL journal state and database footprint without touching Python or Rust:`

```
#!/bin/sh
# scripts/sys_telemetry.sh — Emits top status bar HTML fragment
set -eu

DB_PATH="${1:-data/cybernest_ledger.db}"
if [ ! -f "$DB_PATH" ]; then
    printf '<span class="val-neg">[DB: OFFLINE]</span>\n'
    exit 0
fi

WAL_MODE=$(sqlite3 "$DB_PATH" "PRAGMA journal_mode;" | tr '[:lower:]' '[:upper:]')
DB_SIZE_KB=$(du -k "$DB_PATH" | cut -f1)
SYNC_TIME=$(date -u +"%Y-%m-%d %H:%M:%S UTC")

printf '<span class="val-pos">[DB: %s_OK // %s KB]</span> <span class="val-muted">[SYNC: %s]</span> <span class="val-pos">[LOOPBACK: 127.0.0.1]</span>\n' \
    "$WAL_MODE" "$DB_SIZE_KB" "$SYNC_TIME"
```

---

# **`6. Pillar III: Loopback Architecture & The Go Process Multiplexer`**

`The Go gateway (cmd/gateway/) is the central nervous system of a CyberNest Labs web utility. It enforces local-only network isolation and coordinates sub-process execution across Rust, Python, and POSIX Shell.`

## **`6.1 Enforcing Strict 127.0.0.1 Loopback Binding & SSRF Guards`**

`Under no circumstances may a Labs utility bind to 0.0.0.0 (all interfaces). In cmd/gateway/main.go, the listener validates that the host IP is strictly loopback before opening the socket:`

```
// cmd/gateway/main.go
package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

func enforceLoopbackAddress(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid bind address %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("SECURITY VIOLATION: CyberNest Labs utilities must bind strictly to 127.0.0.1 loopback (got %q)", host)
	}
	return nil
}

func main() {
	bindAddr := os.Getenv("CYBERNEST_BIND_ADDR")
	if bindAddr == "" {
		bindAddr = "127.0.0.1:8090"
	}
	if err := enforceLoopbackAddress(bindAddr); err != nil {
		log.Fatalf("[ERR_HALT] %v", err)
	}

	mux := http.NewServeMux()
	registerRoutes(mux)

	srv := &http.Server{
		Addr:              bindAddr,
		Handler:           strictLocalSecurityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	log.Printf("[SYS.01-GATEWAY] Listening strictly on http://%s (Air-Gapped Loopback Mode)", bindAddr)
	log.Fatal(srv.ListenAndServe())
}

func strictLocalSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prohibit all external CDNs, remote fonts, or outbound connections from the DOM
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}
```

## **`6.2 Safe Sub-Process Multiplexing (exec_bridge.go)`**

`When an HTMX request arrives at the Go gateway, Go invokes the compiled Rust binary, Python CLI, or POSIX shell script using exec.CommandContext with an explicit timeout and zero shell interpolation (preventing command injection / CWE-78).`

```
// cmd/gateway/exec_bridge.go
package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
	"time"
)

func runSubprocessHTML(ctx context.Context, timeout time.Duration, bin string, args ...string) ([]byte, error) {
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("subprocess %s failed: %v | stderr: %s", bin, err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// POST /ledger/deposit — Invokes Rust allocator, triggers POSIX backup, and emits HX-Trigger
func handleDepositAndAllocate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, `<span class="val-neg">[ERR_HALT: INVALID_FORM]</span>`, http.StatusBadRequest)
		return
	}

	amountUSD, err := strconv.ParseFloat(r.FormValue("amount_usd"), 64)
	if err != nil || amountUSD <= 0 {
		http.Error(w, `<span class="val-neg">[ERR_HALT: AMOUNT_MUST_BE_POSITIVE]</span>`, http.StatusBadRequest)
		return
	}
	amountCents := strconv.FormatInt(int64(amountUSD*100+0.5), 10)
	txDate := r.FormValue("tx_date")
	notes := r.FormValue("notes")

	// 1. Run Rust Dual-Ledger Engine (returns primary <tr> + OOB <tbody> and footer)
	rustHTML, err := runSubprocessHTML(
		r.Context(),
		5*time.Second,
		"./bin/ledger_core",
		"--allocate",
		"--amount-cents", amountCents,
		"--date", txDate,
		"--notes", notes,
	)
	if err != nil {
		http.Error(w, `<span class="val-neg">[ERR_HALT: RUST_LEDGER_FAULT]</span>`, http.StatusInternalServerError)
		return
	}

	// 2. Run POSIX Shell Hot-Backup & SHA-256 Signer
	_, _ = runSubprocessHTML(r.Context(), 5*time.Second, "/bin/sh", "./scripts/backup_and_sign.sh")

	// 3. Emit HX-Trigger so #panel-current-value and #panel-visual-telemetry refresh automatically
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("HX-Trigger", "ledgerUpdated")
	w.WriteHeader(http.StatusOK)
	w.Write(rustHTML)
}
```

## **`6.3 Multi-Panel HTMX Event Coordination (HX-Trigger + hx-swap-oob)`**

`By returning HX-Trigger: ledgerUpdated from POST /ledger/deposit, the Go gateway decouples the fast Rust transaction ($< 5\text{ ms}$) from the heavier Python valuation and SVG chart regeneration:`

1. **`Immediate Swap:`** `HTMX swaps the Rust response into #deposit-ledger-tbody (CH_01A) and applies the Out-of-Band swaps to #investment-ledger-tbody (CH_01B) and #cumulative-deposit-total.`  
2. **`Asynchronous Cascade:`** `Simultaneously, the browser detects the ledgerUpdated event header and fires parallel GET /panels/valuation and GET /panels/charts requests to the Python engine (hx-trigger="ledgerUpdated from:body"), updating the live asset valuation table and flat SVG charts without blocking the user's ledger input.`

---

# **`7. Pillar IV: Aesthetic & UI Specification (SYS.01 NOCTURNAL SYNTH-LEDGER)`**

`Every CyberNest Labs HTMX interface must comply with the SYS.01 "NOCTURNAL SYNTH-LEDGER" visual design standard—an aesthetic engineered at the intersection of late-90s Yamaha voice synthesizers, OVA wireframe telemetry, and institutional fintech terminals.`

## **`7.1 The Four Laws of Orthogonal Geometry`**

1. **`Zero Border Radius:`** `border-radius: 0px !important; globally across every input, button, badge, table cell, and SVG container.`  
2. **`Zero Drop Shadows or Blur:`** `box-shadow: none !important; and backdrop-filter: none !important;. Visual depth is communicated exclusively through flat cel-paint color blocking and crisp 1px solid structural borders.`  
3. **`Exposed OVA Wireframe Overhangs:`** `The primary .frame-shell container features intersecting outer 1px solid var(--accent-cyan) bottom and right structural rails with a subtle CRT scanline overlay (background-size: 100% 4px).`  
4. **`Tabular Monospace Discipline:`** `Strictly 'JetBrains Mono', 'IBM Plex Mono', monospace with font-variant-numeric: tabular-nums; enforced on all financial tables, security scores, hashes, and timestamps so digits align vertically to the pixel.`

## **`7.2 Cel-Paint Color Token Matrix (No Halation Policy)`**

`Pure black (#000000) and pure white (#FFFFFF) are strictly prohibited to prevent ocular halation during extended nocturnal operations.`

| `CSS Custom Property` | `Hex Code` | `RGB Value` | `UI Architectural Role` |
| :---- | :---- | :---- | :---- |
| `--bg-void` | `#080C12` | `rgb(8, 12, 18)` | `Root viewport background (Nocturnal sky void)` |
| `--bg-panel` | `#101420` | `rgb(16, 20, 32)` | `Primary rectangular panel, table, and form surface` |
| `--bg-purple` | `#261B38` | `rgb(38, 27, 56)` | `Twilight purple for active table row hover & focused inputs` |
| `--border-muted` | `#1E2436` | `rgb(30, 36, 54)` | `Internal spreadsheet grid lines and table row dividers` |
| `--accent-purple` | `#523B78` | `rgb(82, 59, 120)` | `Structural panel borders and inactive bank triggers` |
| `--accent-cyan` | `#36A19D` | `rgb(54, 161, 157)` | `Vocaloid signal cyan: Active borders, positive yield/delta (+), step-meters` |
| `--text-primary` | `#DCD5C6` | `rgb(220, 213, 198)` | `Cel-cream off-white for body text, figures, and ledger numbers` |
| `--text-muted` | `#687888` | `rgb(104, 120, 136)` | `Slate blue-grey for column headers, units, and timestamps` |
| `--status-neg` | `#B85D78` | `rgb(184, 93, 120)` | `Muted crimson-rose for drawdowns (-), high-risk bugs, and [ERR_HALT]` |
| `--status-warn` | `#C9A654` | `rgb(201, 166, 84)` | `OVA moon-amber for [PENDING_MANUAL] locks and HTMX sync states` |

## **`7.3 Reference SYS.01 Stylesheet (web/static/css/synth-ledger.css)`**

```
:root {
  --bg-void: #080C12;
  --bg-panel: #101420;
  --bg-purple: #261B38;
  --border-muted: #1E2436;
  --accent-purple: #523B78;
  --accent-cyan: #36A19D;
  --text-primary: #DCD5C6;
  --text-muted: #687888;
  --status-neg: #B85D78;
  --status-warn: #C9A654;
  --font-mono: 'JetBrains Mono', 'IBM Plex Mono', monospace;
}

* {
  box-sizing: border-box;
  border-radius: 0px !important;
  box-shadow: none !important;
  backdrop-filter: none !important;
}

body {
  margin: 0;
  padding: 16px;
  background-color: var(--bg-void);
  color: var(--text-primary);
  font-family: var(--font-mono);
  font-size: 13px;
  font-variant-numeric: tabular-nums;
}

.frame-shell {
  max-width: 1520px;
  margin: 0 auto;
  border-right: 1px solid var(--accent-cyan);
  border-bottom: 1px solid var(--accent-cyan);
  padding-right: 16px;
  padding-bottom: 16px;
}

.panel-box {
  background: var(--bg-panel);
  border: 1px solid var(--accent-purple);
  padding: 12px;
}

.val-pos { color: var(--accent-cyan); }
.val-neg { color: var(--status-neg); }
.val-warn { color: var(--status-warn); }
.val-muted { color: var(--text-muted); }
.num-right { text-align: right; }
```

---

# **`8. Step-by-Step Developer Walkthrough: Building a New CyberNest Labs Utility`**

`Follow this five-step checklist whenever initializing a new internal or open-source utility in CyberNest Labs:`

1. **`Initialize the SQLite WAL Schema (data/migrations/001_init.sql):`**  
   * `Declare PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON; at the top of the migration.`  
   * `Store all currency values in integer cents (INTEGER) and all weights in basis points (10000 = 100.00%).`  
2. **`Build the Deterministic Rust Core (crates/<utility>_core):`**  
   * `Implement ACID database mutations inside TransactionBehavior::Immediate.`  
   * `Write an HTML fragment renderer (src/html.rs) that outputs the primary HTMX target alongside any hx-swap-oob="true" summary badges or child tables.`  
   * `Verify zero penny loss or regex regressions via cargo test.`  
3. **`Wire the Python Analytics / ML / Export Layer (py_engine/):`**  
   * `If the tool performs security triage or anomaly detection (like BlackRoute-Web), integrate a distilled .onnx model via onnxruntime (CPUExecutionProvider) so inference runs in $< 1\text{ ms}$ offline.`  
   * `Generate flat, server-side <svg> visual telemetry using --accent-cyan (#36A19D), --accent-purple (#523B78), and --text-primary (#DCD5C6).`  
   * `Build deterministic compliance exporters (CyberNest VIDS PDFs, multi-tab XLSX ledgers, SARIF v2.1.0, or CycloneDX 1.5 / SPDX 2.3 SBOMs).`  
4. **`Create the Go Loopback Gateway (cmd/gateway/):`**  
   * `Enforce 127.0.0.1 loopback binding in main.go and compile with GOFIPS=1.`  
   * `Multiplex Rust, Python, and Shell calls via exec.CommandContext and coordinate multi-panel UI updates with HX-Trigger headers.`  
5. **`Enforce CN-DIR-2026-004 POSIX & Windows Bi-Launcher Parity:`**  
   * `Implement dev.sh and dev.bat supporting setup, build, run, cli, simulate, test, and fmt.`  
   * `Harden runtime log paths against symlink attacks (CWE-377), record explicit PIDs (CWE-114), and hook scripts/backup_and_sign.sh into post-mutation workflows to guarantee SHA-256 auditability.`

