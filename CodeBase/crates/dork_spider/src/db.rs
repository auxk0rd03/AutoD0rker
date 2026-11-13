use crate::ast_verifier::{VerificationStats, VerifiedMatch};
use crate::dork_ast::CompiledDorkRule;
use crate::spider::{CHROME_UA, SpiderResult};
use rusqlite::{Connection, Result, TransactionBehavior, params};
use sha2::{Digest, Sha256};

const INIT_SCHEMA_SQL: &str = include_str!("../../../data/migrations/001_init_schema.sql");

pub fn open_wal_db(db_path: &str) -> Result<Connection> {
    let conn = Connection::open(db_path)?;
    conn.execute_batch(INIT_SCHEMA_SQL)?;
    conn.busy_timeout(std::time::Duration::from_millis(5000))?;
    Ok(conn)
}

pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    result.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn ingest_dork_catalog(conn: &mut Connection, rules: &[CompiledDorkRule]) -> Result<usize> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut count = 0usize;

    for rule in rules {
        let ast_json = serde_json::to_string(&rule.expr_tree).unwrap_or_else(|_| "{}".to_string());
        tx.execute(
            "INSERT INTO dork_catalog (category, is_chain, dork_string, compiled_ast_json, default_severity, cwe_id, notes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(dork_string) DO UPDATE SET
                category = excluded.category,
                is_chain = excluded.is_chain,
                compiled_ast_json = excluded.compiled_ast_json,
                default_severity = excluded.default_severity,
                cwe_id = excluded.cwe_id,
                notes = excluded.notes",
            params![
                rule.category,
                if rule.is_chain { 1 } else { 0 },
                rule.raw_dork,
                ast_json,
                rule.default_severity,
                rule.cwe_id,
                rule.notes
            ],
        )?;
        count += 1;
    }

    tx.commit()?;
    Ok(count)
}

pub fn load_catalog_rules(conn: &Connection) -> Result<Vec<CompiledDorkRule>> {
    let mut stmt = conn.prepare(
        "SELECT dork_id, category, is_chain, dork_string, compiled_ast_json, default_severity, cwe_id, COALESCE(notes, '')
         FROM dork_catalog ORDER BY dork_id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        let dork_id: i64 = row.get(0)?;
        let category: String = row.get(1)?;
        let is_chain: i64 = row.get(2)?;
        let raw_dork: String = row.get(3)?;
        let ast_json: String = row.get(4)?;
        let default_severity: String = row.get(5)?;
        let cwe_id: String = row.get(6)?;
        let notes: String = row.get(7)?;
        let expr_tree = serde_json::from_str(&ast_json)
            .unwrap_or_else(|_| crate::dork_ast::parse_dork_string(&raw_dork));
        let candidate_probe_paths = crate::dork_ast::synthesize_probe_paths(&expr_tree);
        Ok(CompiledDorkRule {
            rule_id: dork_id,
            category,
            is_chain: is_chain != 0,
            raw_dork,
            notes,
            default_severity,
            cwe_id,
            expr_tree,
            candidate_probe_paths,
        })
    })?;

    let mut rules = Vec::new();
    for r in rows {
        rules.push(r?);
    }
    Ok(rules)
}

pub fn build_stealth_curl_poc(endpoint: &str, engagement_id: Option<&str>) -> String {
    let safe_url = endpoint.replace('"', "%22").replace('\'', "%27");
    let mut cmd = format!(
        "curl -s -i \"{}\" \\\n  -H \"User-Agent: {}\" \\\n  -H \"Sec-Ch-Ua: \\\"Chromium\\\";v=\\\"124\\\", \\\"Google Chrome\\\";v=\\\"124\\\", \\\"Not-A.Brand\\\";v=\\\"99\\\"\" \\\n  -H \"Sec-Ch-Ua-Mobile: ?0\" \\\n  -H \"Sec-Ch-Ua-Platform: \\\"Linux\\\"\" \\\n  -H \"Sec-Fetch-Dest: document\" \\\n  -H \"Sec-Fetch-Mode: navigate\" \\\n  -H \"Sec-Fetch-Site: none\" \\\n  -H \"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\" \\\n  -H \"Accept-Language: en-US,en;q=0.9\"",
        safe_url, CHROME_UA
    );
    if let Some(eng) = engagement_id {
        let clean: String = eng
            .chars()
            .filter(|&c| c != '\r' && c != '\n' && c != '"' && c != '\0')
            .collect();
        if !clean.is_empty() {
            cmd.push_str(&format!(
                " \\\n  -H \"X-Security-Engagement: {}\" \\\n  -H \"X-Authorized-Audit: true\"",
                clean
            ));
        }
    }
    cmd
}

pub fn build_remediation(category: &str, cwe_id: &str) -> String {
    let lower = category.to_ascii_lowercase();
    if lower.contains("passwords") || cwe_id == "CWE-798" {
        "Revoke and rotate exposed credentials immediately; migrate secrets to an encrypted vault or runtime environment injection outside web-served directories.".to_string()
    } else if lower.contains("login portals") || cwe_id == "CWE-287" {
        "Restrict administrative/staging login portals via VPN, mTLS, or Zero-Trust SSO allowlists; enforce MFA and rate limiting.".to_string()
    } else if lower.contains("sensitive directories") || cwe_id == "CWE-538" {
        "Disable directory auto-indexing (Options -Indexes / autoindex off), block public access to internal configuration files, and purge backup/archive artifacts from webroots.".to_string()
    } else if lower.contains("online devices") || cwe_id == "CWE-16" {
        "Isolate management interfaces onto private management VLANs and disable unauthenticated device telemetry pages.".to_string()
    } else {
        "Remove sensitive diagnostic endpoints from public internet exposure, sanitize configuration responses, and validate access controls.".to_string()
    }
}

/// Normalized Surface Risk Score (0-100) matching BlackRoute-Web Section 6.10:
/// Vendor/INFO capped at +2 total; CRITICAL=+25, HIGH=+15, MEDIUM=+8, LOW=+3, unique endpoints=+3 (max +15).
pub fn compute_surface_risk_score(findings: &[VerifiedMatch]) -> i64 {
    if findings.is_empty() {
        return 0;
    }
    let mut score: i64 = 10;
    let mut vendor_info_pts: i64 = 0;
    let mut unique_endpoints = std::collections::HashSet::new();

    for f in findings {
        if f.is_vendor_observation || f.severity == "INFO" {
            vendor_info_pts = (vendor_info_pts + 1).min(2);
            continue;
        }
        unique_endpoints.insert(f.matched_endpoint.clone());
        score += match f.severity.as_str() {
            "CRITICAL" => 25,
            "HIGH" => 15,
            "MEDIUM" => 8,
            "LOW" => 3,
            _ => 0,
        };
    }
    let endpoint_bonus = ((unique_endpoints.len() as i64) * 3).min(15);
    (score + vendor_info_pts + endpoint_bonus).clamp(0, 100)
}

pub struct ScanPersistParams<'a> {
    pub batch_id: &'a str,
    pub batch_index: i64,
    pub target_url: &'a str,
    pub scan_profile: &'a str,
    pub shadow_mode: bool,
    pub engagement_id: Option<&'a str>,
    pub dorks_evaluated: i64,
    pub output_dir_rel: &'a str,
}

pub fn persist_scan_results(
    conn: &mut Connection,
    params_in: &ScanPersistParams<'_>,
    spider_res: &SpiderResult,
    findings: &[VerifiedMatch],
    stats: &VerificationStats,
) -> Result<(i64, i64)> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    let risk_score = compute_surface_risk_score(findings);
    let total_pages = spider_res.docs.len() as i64;
    let status = if spider_res.waf_tripped {
        "HALTED_WAF"
    } else {
        "COMPLETED"
    };
    let host_hash = sha256_hex(params_in.target_url);

    tx.execute(
        "INSERT INTO scan_sessions (
            batch_id, batch_index, target_url, target_host_hash, scan_profile,
            shadow_mode, engagement_id, pages_crawled, dorks_evaluated,
            surface_risk_score, baseline_404_simhash, detected_waf_vendor, status, output_dir_rel
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            params_in.batch_id,
            params_in.batch_index,
            params_in.target_url,
            host_hash,
            params_in.scan_profile,
            if params_in.shadow_mode { 1 } else { 0 },
            params_in.engagement_id,
            total_pages,
            params_in.dorks_evaluated,
            risk_score,
            spider_res.baseline_404_simhash_hex,
            spider_res.detected_waf_vendor,
            status,
            params_in.output_dir_rel,
        ],
    )?;
    let scan_id = tx.last_insert_rowid();

    let mut cat_counts = std::collections::BTreeMap::<String, i64>::new();
    for f in findings {
        *cat_counts.entry(f.category.clone()).or_insert(0) += 1;
        let dedup_hash = sha256_hex(&format!(
            "{}:{}:{}:{}",
            scan_id, f.rule_id, f.matched_endpoint, f.ast_node_type
        ));
        let curl_poc = build_stealth_curl_poc(&f.matched_endpoint, params_in.engagement_id);
        let remediation = build_remediation(&f.category, &f.cwe_id);

        tx.execute(
            "INSERT OR IGNORE INTO dork_findings (
                scan_id, dork_id, exact_dedup_hash, severity, cwe_id, cvss_vector,
                cvss_score_bps, matched_endpoint, ast_node_type, ast_context_snippet,
                shannon_entropy_bps, confidence_bps, stealth_curl_poc, remediation, is_suppressed_fp
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                scan_id,
                f.rule_id,
                dedup_hash,
                f.severity,
                f.cwe_id,
                f.cvss_vector,
                f.cvss_score_bps,
                f.matched_endpoint,
                f.ast_node_type,
                f.ast_context_snippet,
                f.shannon_entropy_bps,
                f.confidence_bps,
                curl_poc,
                remediation,
                if f.is_shadow_downgraded { 1 } else { 0 },
            ],
        )?;
    }

    // Persist harvested endpoints
    for doc in &spider_res.docs {
        let src_type = match doc.doc_kind {
            crate::ast_verifier::DocKind::Html => "HTML",
            crate::ast_verifier::DocKind::JavaScript => "JS",
            crate::ast_verifier::DocKind::Json => "JSON",
            crate::ast_verifier::DocKind::Yaml => "YAML",
            crate::ast_verifier::DocKind::Sql => "SQL",
            crate::ast_verifier::DocKind::Config => "CONFIG",
            crate::ast_verifier::DocKind::Log => "LOG",
            crate::ast_verifier::DocKind::Text => "TEXT",
        };
        tx.execute(
            "INSERT OR IGNORE INTO harvested_endpoints (scan_id, endpoint_url, source_type, http_status, is_vendor_asset)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                scan_id,
                doc.url,
                src_type,
                doc.status_code as i64,
                if doc.is_vendor_asset { 1 } else { 0 },
            ],
        )?;
    }

    let cat_json = serde_json::to_string(&cat_counts).unwrap_or_else(|_| "{}".to_string());
    let vendor_json =
        serde_json::to_string(&spider_res.vendor_observations).unwrap_or_else(|_| "[]".to_string());
    let tech_json =
        serde_json::to_string(&spider_res.technologies).unwrap_or_else(|_| "[]".to_string());

    tx.execute(
        "INSERT INTO scan_telemetry (
            scan_id, html_pages_crawled, js_files_crawled, config_files_crawled,
            total_assets_crawled, raw_dork_candidates, ast_fp_dropped,
            soft404_fp_dropped, entropy_fp_dropped, baseline_latency_mean_ms,
            baseline_404_entropy_bps, category_hits_json, vendor_observations_json, technologies_json
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            scan_id,
            spider_res.html_pages_crawled,
            spider_res.js_files_crawled,
            spider_res.config_files_crawled,
            total_pages,
            stats.raw_candidates,
            stats.ast_fp_dropped,
            stats.soft404_fp_dropped,
            stats.entropy_fp_dropped,
            spider_res.baseline_latency_mean_ms,
            spider_res.baseline_404_entropy_bps,
            cat_json,
            vendor_json,
            tech_json,
        ],
    )?;

    tx.commit()?;
    Ok((scan_id, risk_score))
}

pub fn query_batch_kpis(conn: &Connection, batch_id: &str) -> Result<(i64, i64, i64, i64, i64)> {
    let targets: i64 = conn.query_row(
        "SELECT COUNT(*) FROM scan_sessions WHERE batch_id = ?1",
        params![batch_id],
        |r| r.get(0),
    )?;
    let dorks_run: i64 = conn.query_row(
        "SELECT COALESCE(SUM(dorks_evaluated), 0) FROM scan_sessions WHERE batch_id = ?1",
        params![batch_id],
        |r| r.get(0),
    )?;
    let verified_tp: i64 = conn.query_row(
        "SELECT COUNT(*) FROM dork_findings df
         JOIN scan_sessions ss ON df.scan_id = ss.scan_id
         WHERE ss.batch_id = ?1 AND df.is_suppressed_fp = 0",
        params![batch_id],
        |r| r.get(0),
    )?;
    let fp_dropped: i64 = conn.query_row(
        "SELECT COALESCE(SUM(st.ast_fp_dropped + st.soft404_fp_dropped + st.entropy_fp_dropped), 0)
         FROM scan_telemetry st
         JOIN scan_sessions ss ON st.scan_id = ss.scan_id
         WHERE ss.batch_id = ?1",
        params![batch_id],
        |r| r.get(0),
    )?;
    let max_risk: i64 = conn.query_row(
        "SELECT COALESCE(MAX(surface_risk_score), 0) FROM scan_sessions WHERE batch_id = ?1",
        params![batch_id],
        |r| r.get(0),
    )?;
    Ok((targets, dorks_run, verified_tp, fp_dropped, max_risk))
}
