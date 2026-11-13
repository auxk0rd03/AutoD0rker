use dork_spider::ast_verifier::verify_rules_against_docs;
use dork_spider::db::{
    ScanPersistParams, ingest_dork_catalog, load_catalog_rules, open_wal_db, persist_scan_results,
};
use dork_spider::dork_ast::load_dorkset_csv;
use dork_spider::html::render_scan_htmx_response;
use dork_spider::spider::{PROBE_JITTER_MAX_MS, PROBE_JITTER_MIN_MS, SpiderConfig, run_spider};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};
use std::env;
use std::path::PathBuf;
use std::process;

fn get_arg(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn default_db_path() -> String {
    env::var("AUTODORKER_DB_PATH").unwrap_or_else(|_| "data/autodorker_state.db".to_string())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "Usage: dork_spider [--ingest-csv <path>] [--scan --target <url> ...] [--render --scan-id <id>]"
        );
        process::exit(1);
    }

    let db_path = get_arg(&args, "--db").unwrap_or_else(default_db_path);
    if let Some(parent) = std::path::Path::new(&db_path).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }

    if let Some(csv_path) = get_arg(&args, "--ingest-csv") {
        let mut conn = match open_wal_db(&db_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[ERR] Failed opening DB {}: {}", db_path, e);
                process::exit(1);
            }
        };
        let rules = match load_dorkset_csv(std::path::Path::new(&csv_path)) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[ERR] {}", e);
                process::exit(1);
            }
        };
        match ingest_dork_catalog(&mut conn, &rules) {
            Ok(n) => {
                let chain_cnt = rules.iter().filter(|r| r.is_chain).count();
                println!(
                    "{}",
                    json!({
                        "status": "OK",
                        "ingested": n,
                        "chain_rules": chain_cnt,
                        "atomic_rules": n.saturating_sub(chain_cnt),
                        "db_path": db_path
                    })
                );
            }
            Err(e) => {
                eprintln!("[ERR] Failed ingesting catalog: {}", e);
                process::exit(1);
            }
        }
        return;
    }

    if has_flag(&args, "--scan") {
        let target = match get_arg(&args, "--target") {
            Some(t) => t,
            None => {
                eprintln!("[ERR] --scan requires --target <url>");
                process::exit(1);
            }
        };
        let batch_id = get_arg(&args, "--batch-id").unwrap_or_else(|| "single".to_string());
        let batch_index: i64 = get_arg(&args, "--batch-index")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);
        let depth: usize = get_arg(&args, "--depth")
            .and_then(|s| s.parse().ok())
            .unwrap_or(2);
        let stealth_mode = !has_flag(&args, "--active");
        let shadow_mode = has_flag(&args, "--shadow");
        let allow_local = has_flag(&args, "--allow-local");
        let engagement_id = get_arg(&args, "--engagement-id").filter(|s| !s.trim().is_empty());
        let output_dir_rel =
            get_arg(&args, "--out-rel").unwrap_or_else(|| format!("Output/Targ{:03}", batch_index));
        let harvest_dir = get_arg(&args, "--harvest-dir").map(PathBuf::from);
        let keep_harvest = has_flag(&args, "--keep-harvest");
        let emit_json = has_flag(&args, "--json");
        let jitter_min_ms: u64 = get_arg(&args, "--jitter-min-ms")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(PROBE_JITTER_MIN_MS)
            .min(30_000);
        let jitter_max_ms: u64 = get_arg(&args, "--jitter-max-ms")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(PROBE_JITTER_MAX_MS)
            .min(60_000)
            .max(jitter_min_ms);
        let proxy_url = get_arg(&args, "--proxy")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let category_filter: Vec<String> = get_arg(&args, "--categories")
            .map(|raw| {
                raw.split(',')
                    .map(|c| c.trim().to_ascii_lowercase())
                    .filter(|c| !c.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let custom_wordlist: Vec<String> = get_arg(&args, "--wordlist")
            .map(|raw| {
                raw.split(|c| c == ',' || c == '\n' || c == '\r')
                    .map(|w| w.trim().to_string())
                    .filter(|w| !w.is_empty())
                    .take(256)
                    .collect()
            })
            .unwrap_or_default();
        let spa_seed_path = get_arg(&args, "--spa-seed")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);

        let mut conn = match open_wal_db(&db_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[ERR] DB error: {}", e);
                process::exit(1);
            }
        };

        let mut rules = load_catalog_rules(&conn).unwrap_or_default();
        if rules.is_empty() {
            // Attempt automatic seed from default ../Docs/DorkSet.csv
            let fallback_csv = std::path::Path::new("../Docs/DorkSet.csv");
            if fallback_csv.exists() {
                if let Ok(loaded) = load_dorkset_csv(fallback_csv) {
                    let _ = ingest_dork_catalog(&mut conn, &loaded);
                    rules = load_catalog_rules(&conn).unwrap_or(loaded);
                }
            }
        }
        if !category_filter.is_empty() {
            let filtered: Vec<_> = rules
                .iter()
                .filter(|r| {
                    let cat_l = r.category.to_ascii_lowercase();
                    category_filter.iter().any(|f| cat_l.contains(f))
                })
                .cloned()
                .collect();
            if !filtered.is_empty() {
                rules = filtered;
            }
        }

        let cfg = SpiderConfig {
            target_url: target.clone(),
            max_depth: depth.min(6),
            stealth_mode,
            allow_local_staging: allow_local,
            engagement_id: engagement_id.clone(),
            harvest_dir,
            keep_harvest,
            jitter_min_ms,
            jitter_max_ms,
            proxy_url,
            custom_wordlist,
            spa_seed_path,
        };

        let spider_res = match run_spider(&cfg, &rules) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[ERR] Spider failed for {}: {}", target, e);
                process::exit(1);
            }
        };

        let (verified, stats) = verify_rules_against_docs(
            &rules,
            &spider_res.docs,
            &target,
            spider_res.baseline_404_simhash,
            shadow_mode,
        );

        let scan_profile = if stealth_mode {
            "STEALTH_PASSIVE"
        } else {
            "ACTIVE_VERIFICATION"
        };

        let persist_in = ScanPersistParams {
            batch_id: &batch_id,
            batch_index,
            target_url: &target,
            scan_profile,
            shadow_mode,
            engagement_id: engagement_id.as_deref(),
            dorks_evaluated: rules.len() as i64,
            output_dir_rel: &output_dir_rel,
        };

        let (scan_id, risk_score) =
            match persist_scan_results(&mut conn, &persist_in, &spider_res, &verified, &stats) {
                Ok(res) => res,
                Err(e) => {
                    eprintln!("[ERR] DB persist failed: {}", e);
                    process::exit(1);
                }
            };

        eprintln!(
            "[AST+ENTROPY] Scan #{} complete: raw={} verified={} dropped_ast={} dropped_404={} dropped_entropy={} risk={}/100",
            scan_id,
            stats.raw_candidates,
            verified.len(),
            stats.ast_fp_dropped,
            stats.soft404_fp_dropped,
            stats.entropy_fp_dropped,
            risk_score
        );

        if emit_json {
            println!(
                "{}",
                json!({
                    "scan_id": scan_id,
                    "batch_id": batch_id,
                    "target_url": target,
                    "pages_crawled": spider_res.docs.len(),
                    "dorks_evaluated": rules.len(),
                    "verified_count": verified.len(),
                    "ast_fp_dropped": stats.ast_fp_dropped,
                    "soft404_fp_dropped": stats.soft404_fp_dropped,
                    "entropy_fp_dropped": stats.entropy_fp_dropped,
                    "risk_score": risk_score,
                    "waf_vendor": spider_res.detected_waf_vendor,
                    "waf_tripped": spider_res.waf_tripped,
                    "harvest_dir": spider_res.harvest_dir_used.to_string_lossy()
                })
            );
        } else {
            match render_scan_htmx_response(&conn, scan_id, &batch_id) {
                Ok(html) => print!("{}", html),
                Err(e) => {
                    eprintln!("[ERR] HTML render failed: {}", e);
                    process::exit(1);
                }
            }
        }
        return;
    }

    if has_flag(&args, "--render") {
        let scan_id: i64 = get_arg(&args, "--scan-id")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let conn = match open_wal_db(&db_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[ERR] DB error: {}", e);
                process::exit(1);
            }
        };
        let batch_id: String = get_arg(&args, "--batch-id").unwrap_or_else(|| {
            conn.query_row(
                "SELECT batch_id FROM scan_sessions WHERE scan_id = ?1",
                rusqlite::params![scan_id],
                |r| r.get(0),
            )
            .unwrap_or_else(|_| "single".to_string())
        });
        match render_scan_htmx_response(&conn, scan_id, &batch_id) {
            Ok(html) => print!("{}", html),
            Err(e) => {
                eprintln!("[ERR] Render error: {}", e);
                process::exit(1);
            }
        }
        return;
    }

    if has_flag(&args, "--latest-state-json") {
        let conn = match open_wal_db(&db_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[ERR] DB error: {}", e);
                process::exit(1);
            }
        };
        let dork_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM dork_catalog", [], |r| r.get(0))
            .unwrap_or(0);
        let chain_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM dork_catalog WHERE is_chain = 1",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let latest = conn.query_row(
            "SELECT scan_id, batch_id, target_url, surface_risk_score FROM scan_sessions ORDER BY scan_id DESC LIMIT 1",
            [],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?)),
        );
        match latest {
            Ok((sid, bid, target, risk)) => {
                let kpis =
                    dork_spider::db::query_batch_kpis(&conn, &bid).unwrap_or((0, 0, 0, 0, 0));
                println!(
                    "{}",
                    json!({
                        "dork_count": dork_count,
                        "chain_count": chain_count,
                        "latest_scan_id": sid,
                        "latest_batch_id": bid,
                        "latest_target": target,
                        "targets": kpis.0,
                        "dorks_run": kpis.1,
                        "verified_tp": kpis.2,
                        "fp_dropped": kpis.3,
                        "max_risk": risk.max(kpis.4)
                    })
                );
            }
            Err(_) => {
                println!(
                    "{}",
                    json!({
                        "dork_count": dork_count,
                        "chain_count": chain_count,
                        "latest_scan_id": 0,
                        "latest_batch_id": "",
                        "latest_target": "",
                        "targets": 0,
                        "dorks_run": 0,
                        "verified_tp": 0,
                        "fp_dropped": 0,
                        "max_risk": 0
                    })
                );
            }
        }
        return;
    }

    if has_flag(&args, "--history-json") {
        let limit: i64 = get_arg(&args, "--limit")
            .and_then(|s| s.parse().ok())
            .unwrap_or(40)
            .clamp(1, 200);
        let conn = match open_wal_db(&db_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[ERR] DB error: {}", e);
                process::exit(1);
            }
        };
        let mut stmt = conn
            .prepare(
                "SELECT s.scan_id, s.batch_id, s.batch_index, s.target_url, s.scan_profile,
                        s.shadow_mode, s.pages_crawled, s.dorks_evaluated, s.surface_risk_score,
                        s.detected_waf_vendor, s.status, s.created_at,
                        (SELECT COUNT(*) FROM dork_findings f WHERE f.scan_id = s.scan_id AND f.is_suppressed_fp = 0) AS verified_count
                 FROM scan_sessions s
                 ORDER BY s.scan_id DESC
                 LIMIT ?1",
            )
            .expect("valid history SQL");
        let rows = stmt
            .query_map(rusqlite::params![limit], |r| {
                Ok(json!({
                    "scan_id": r.get::<_, i64>(0)?,
                    "batch_id": r.get::<_, String>(1)?,
                    "batch_index": r.get::<_, i64>(2)?,
                    "target_url": r.get::<_, String>(3)?,
                    "scan_profile": r.get::<_, String>(4)?,
                    "shadow_mode": r.get::<_, i64>(5)? != 0,
                    "pages_crawled": r.get::<_, i64>(6)?,
                    "dorks_evaluated": r.get::<_, i64>(7)?,
                    "surface_risk_score": r.get::<_, i64>(8)?,
                    "detected_waf_vendor": r.get::<_, String>(9)?,
                    "status": r.get::<_, String>(10)?,
                    "created_at": r.get::<_, String>(11)?,
                    "verified_count": r.get::<_, i64>(12)?
                }))
            })
            .expect("query history");
        let scans: Vec<Value> = rows.filter_map(Result::ok).collect();
        let mut batch_map: BTreeMap<String, (i64, usize, i64, String)> = BTreeMap::new();
        for s in &scans {
            if let (Some(bid), Some(sid), Some(risk), Some(ts)) = (
                s.get("batch_id").and_then(|v| v.as_str()),
                s.get("scan_id").and_then(|v| v.as_i64()),
                s.get("surface_risk_score").and_then(|v| v.as_i64()),
                s.get("created_at").and_then(|v| v.as_str()),
            ) {
                let entry =
                    batch_map
                        .entry(bid.to_string())
                        .or_insert((sid, 0, risk, ts.to_string()));
                if sid > entry.0 {
                    entry.0 = sid;
                    entry.3 = ts.to_string();
                }
                entry.1 += 1;
                if risk > entry.2 {
                    entry.2 = risk;
                }
            }
        }
        let mut batches: Vec<Value> = batch_map
            .into_iter()
            .map(|(bid, (latest_sid, target_count, max_risk, created_at))| {
                json!({
                    "batch_id": bid,
                    "latest_scan_id": latest_sid,
                    "target_count": target_count,
                    "max_risk": max_risk,
                    "created_at": created_at
                })
            })
            .collect();
        batches.sort_by(|a, b| {
            b.get("latest_scan_id")
                .and_then(|v| v.as_i64())
                .cmp(&a.get("latest_scan_id").and_then(|v| v.as_i64()))
        });
        println!("{}", json!({ "scans": scans, "batches": batches }));
        return;
    }

    if has_flag(&args, "--categories-json") {
        let conn = match open_wal_db(&db_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[ERR] DB error: {}", e);
                process::exit(1);
            }
        };
        let mut stmt = conn
            .prepare(
                "SELECT category, COUNT(*) AS cnt, MAX(is_chain) AS is_chain
                 FROM dork_catalog
                 GROUP BY category
                 ORDER BY is_chain DESC, cnt DESC, category ASC",
            )
            .expect("valid categories SQL");
        let cats: Vec<Value> = stmt
            .query_map([], |r| {
                Ok(json!({
                    "category": r.get::<_, String>(0)?,
                    "count": r.get::<_, i64>(1)?,
                    "is_chain": r.get::<_, i64>(2)? != 0
                }))
            })
            .expect("query categories")
            .filter_map(Result::ok)
            .collect();
        println!("{}", json!({ "categories": cats }));
        return;
    }

    if has_flag(&args, "--compare-scans") {
        let scan_a: i64 = get_arg(&args, "--scan-a")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let scan_b: i64 = get_arg(&args, "--scan-b")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if scan_a <= 0 || scan_b <= 0 {
            eprintln!("[ERR] --compare-scans requires --scan-a <id> and --scan-b <id>");
            process::exit(1);
        }
        let conn = match open_wal_db(&db_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[ERR] DB error: {}", e);
                process::exit(1);
            }
        };
        let load_scan_meta = |sid: i64| -> Option<Value> {
            conn.query_row(
                "SELECT scan_id, batch_id, target_url, surface_risk_score, status, created_at
                 FROM scan_sessions WHERE scan_id = ?1",
                rusqlite::params![sid],
                |r| {
                    Ok(json!({
                        "scan_id": r.get::<_, i64>(0)?,
                        "batch_id": r.get::<_, String>(1)?,
                        "target_url": r.get::<_, String>(2)?,
                        "surface_risk_score": r.get::<_, i64>(3)?,
                        "status": r.get::<_, String>(4)?,
                        "created_at": r.get::<_, String>(5)?
                    }))
                },
            )
            .ok()
        };
        let Some(meta_a) = load_scan_meta(scan_a) else {
            eprintln!("[ERR] Scan #{} not found", scan_a);
            process::exit(1);
        };
        let Some(meta_b) = load_scan_meta(scan_b) else {
            eprintln!("[ERR] Scan #{} not found", scan_b);
            process::exit(1);
        };
        let load_findings = |sid: i64| -> Vec<(String, Value)> {
            let mut stmt = conn
                .prepare(
                    "SELECT f.dork_id, c.category, c.dork_string, f.severity, f.cwe_id,
                            f.matched_endpoint, f.ast_node_type, f.cvss_score_bps
                     FROM dork_findings f
                     JOIN dork_catalog c ON c.dork_id = f.dork_id
                     WHERE f.scan_id = ?1 AND f.is_suppressed_fp = 0
                     ORDER BY f.cvss_score_bps DESC, f.finding_id ASC",
                )
                .expect("valid compare SQL");
            stmt.query_map(rusqlite::params![sid], |r| {
                let dork_id = r.get::<_, i64>(0)?;
                let ep = r.get::<_, String>(5)?;
                let node = r.get::<_, String>(6)?;
                let key = format!("{}:{}:{}", dork_id, node, ep);
                Ok((
                    key,
                    json!({
                        "dork_id": dork_id,
                        "category": r.get::<_, String>(1)?,
                        "dork_string": r.get::<_, String>(2)?,
                        "severity": r.get::<_, String>(3)?,
                        "cwe_id": r.get::<_, String>(4)?,
                        "matched_endpoint": ep,
                        "ast_node_type": node,
                        "cvss_score_bps": r.get::<_, i64>(7)?
                    }),
                ))
            })
            .expect("query compare")
            .filter_map(Result::ok)
            .collect()
        };
        let list_a = load_findings(scan_a);
        let list_b = load_findings(scan_b);
        let keys_a: HashSet<String> = list_a.iter().map(|(k, _)| k.clone()).collect();
        let keys_b: HashSet<String> = list_b.iter().map(|(k, _)| k.clone()).collect();
        let resolved: Vec<Value> = list_a
            .iter()
            .filter(|(k, _)| !keys_b.contains(k))
            .map(|(_, v)| v.clone())
            .collect();
        let added: Vec<Value> = list_b
            .iter()
            .filter(|(k, _)| !keys_a.contains(k))
            .map(|(_, v)| v.clone())
            .collect();
        let unchanged: Vec<Value> = list_b
            .iter()
            .filter(|(k, _)| keys_a.contains(k))
            .map(|(_, v)| v.clone())
            .collect();
        let risk_a = meta_a
            .get("surface_risk_score")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let risk_b = meta_b
            .get("surface_risk_score")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        println!(
            "{}",
            json!({
                "scan_a": meta_a,
                "scan_b": meta_b,
                "risk_delta": risk_b - risk_a,
                "added_count": added.len(),
                "resolved_count": resolved.len(),
                "unchanged_count": unchanged.len(),
                "added": added,
                "resolved": resolved,
                "unchanged": unchanged
            })
        );
        return;
    }

    eprintln!("[ERR] Unknown mode");
    process::exit(1);
}
