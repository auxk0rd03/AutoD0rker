-- CyberNest Labs: AutoDorker SQLite3 WAL Persistence Schema
-- Compliance: CN-LABS-H2C-2026-01, CN-LABS-BRW-2026-02
-- Numeric Determinism: CVSS, Entropy H(X), and Confidence stored as integer basis points (i64).

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
    cvss_score_bps INTEGER NOT NULL,      -- Stored in basis points (e.g., 750 = 7.5) for zero float drift
    matched_endpoint TEXT NOT NULL,
    ast_node_type TEXT NOT NULL,          -- e.g., 'DOM_TITLE', 'DOM_DIR_INDEX', 'JS_OBJ_PROP', 'YAML_KEY'
    ast_context_snippet TEXT NOT NULL,
    shannon_entropy_bps INTEGER NOT NULL, -- Stored in basis points (e.g., 342 = 3.42 bits/char)
    confidence_bps INTEGER NOT NULL,      -- Stored in basis points (e.g., 9500 = 95.00%)
    stealth_curl_poc TEXT NOT NULL,
    remediation TEXT NOT NULL,
    is_suppressed_fp INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- 4. Scan Telemetry & False-Positive Suppression Ledger
CREATE TABLE IF NOT EXISTS scan_telemetry (
    scan_id INTEGER PRIMARY KEY REFERENCES scan_sessions(scan_id) ON DELETE CASCADE,
    html_pages_crawled INTEGER NOT NULL DEFAULT 0,
    js_files_crawled INTEGER NOT NULL DEFAULT 0,
    config_files_crawled INTEGER NOT NULL DEFAULT 0,
    total_assets_crawled INTEGER NOT NULL DEFAULT 0,
    raw_dork_candidates INTEGER NOT NULL DEFAULT 0,
    ast_fp_dropped INTEGER NOT NULL DEFAULT 0,
    soft404_fp_dropped INTEGER NOT NULL DEFAULT 0,
    entropy_fp_dropped INTEGER NOT NULL DEFAULT 0,
    baseline_latency_mean_ms INTEGER NOT NULL DEFAULT 0,
    baseline_404_entropy_bps INTEGER NOT NULL DEFAULT 0,
    category_hits_json TEXT NOT NULL DEFAULT '{}',
    vendor_observations_json TEXT NOT NULL DEFAULT '[]',
    technologies_json TEXT NOT NULL DEFAULT '[]',
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- 5. Harvested Endpoints & Routes per Scan
CREATE TABLE IF NOT EXISTS harvested_endpoints (
    endpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scan_sessions(scan_id) ON DELETE CASCADE,
    endpoint_url TEXT NOT NULL,
    source_type TEXT NOT NULL,
    http_status INTEGER NOT NULL DEFAULT 0,
    is_vendor_asset INTEGER NOT NULL DEFAULT 0,
    UNIQUE(scan_id, endpoint_url)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON dork_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_dork_id ON dork_findings(dork_id);
CREATE INDEX IF NOT EXISTS idx_sessions_batch_id ON scan_sessions(batch_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_scan_id ON harvested_endpoints(scan_id);
