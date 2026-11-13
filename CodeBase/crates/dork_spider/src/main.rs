use dork_spider::ast_verifier::verify_rules_against_docs;
use dork_spider::db::{
    ScanPersistParams, ingest_dork_catalog, load_catalog_rules, open_wal_db, persist_scan_results,
};
use dork_spider::dork_ast::load_dorkset_csv;
use dork_spider::html::render_scan_htmx_response;
use dork_spider::spider::{SpiderConfig, run_spider};
use serde_json::json;
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

        let cfg = SpiderConfig {
            target_url: target.clone(),
            max_depth: depth,
            stealth_mode,
            allow_local_staging: allow_local,
            engagement_id: engagement_id.clone(),
            harvest_dir,
            keep_harvest,
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

    eprintln!("[ERR] Unknown mode");
    process::exit(1);
}
