use dork_spider::ast_verifier::{
    build_harvested_doc, strip_js_comments, verify_rules_against_docs,
};
use dork_spider::db::{ingest_dork_catalog, load_catalog_rules, open_wal_db};
use dork_spider::dork_ast::{
    DorkExpr, DorkOperator, load_dorkset_csv, parse_dork_string, synthesize_probe_paths,
};
use dork_spider::entropy::{
    dom_tag_simhash, evaluate_secret_candidates, shannon_entropy, shannon_entropy_bps,
    simhash_similarity_bps,
};
use std::path::{Path, PathBuf};

fn dorkset_csv_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../Docs/DorkSet.csv")
}

#[test]
fn test_load_all_295_dorkset_rules() {
    let csv_path = dorkset_csv_path();
    assert!(
        csv_path.exists(),
        "Docs/DorkSet.csv must exist at {:?}",
        csv_path
    );
    let rules = load_dorkset_csv(&csv_path).expect("CSV should load cleanly");
    assert_eq!(rules.len(), 295, "Expected exactly 295 dork rules");
    let chains = rules.iter().filter(|r| r.is_chain).count();
    assert_eq!(chains, 32, "Expected 32 [CHAIN] rules");
    assert_eq!(rules.len() - chains, 263, "Expected 263 atomic rules");

    for r in &rules {
        let json = serde_json::to_string(&r.expr_tree).expect("AST serializable");
        assert!(!json.is_empty());
    }
}

#[test]
fn test_boolean_dork_ast_precedence_and_quirks() {
    // Tight pipe binding inside unparenthesized conjunction
    let ast = parse_dork_string(
        r#"intext:"aws_access_key_id" | intext:"aws_secret_access_key" filetype:json | filetype:yaml"#,
    );
    match ast {
        DorkExpr::And(parts) => {
            assert_eq!(parts.len(), 2);
            assert!(matches!(parts[0], DorkExpr::Or(_)));
            assert!(matches!(parts[1], DorkExpr::Or(_)));
        }
        other => panic!("Expected And([Or, Or]), got {:?}", other),
    }

    // Exclusion & probe synthesis
    let ast2 = parse_dork_string(r#"intext:"siemens" & inurl:"/portal/portal.mwsl""#);
    let probes = synthesize_probe_paths(&ast2);
    assert!(probes.contains(&"/portal/portal.mwsl".to_string()));

    let ast3 = parse_dork_string(r#"intitle:"SSL Network Extender Login" -checkpoint.com"#);
    match ast3 {
        DorkExpr::And(parts) => {
            assert!(matches!(parts[1], DorkExpr::Not(_)));
        }
        _ => panic!("Expected And with Not exclusion"),
    }

    // Malformed legacy quotes must not panic
    let _ = parse_dork_string(r#"intitle:'Sypex Dumper" inurl:sxd"#);
    let _ = parse_dork_string(r#"allintitle:"Login | wplogin Login"#);
}

#[test]
fn test_shannon_entropy_math_and_honeypot_suppression() {
    assert!(shannon_entropy("AAAAAAAAAAAAAAAAAAAA") < 0.01);
    assert_eq!(shannon_entropy_bps("AAAAAAAAAAAAAAAAAAAA"), 0);

    // High entropy realistic key
    let real_key = concat!("AKIA", "9X4K2M8P3Q7R5T1W");
    let real_bps = shannon_entropy_bps(real_key);
    assert!(
        real_bps >= 300,
        "Expected >= 300 bps for realistic AWS key, got {}",
        real_bps
    );

    // Placeholder detection
    let dummy_text =
        r#"{"aws_access_key_id": "AKIAXXXXXXXXXXXXXXXX", "api_key": "YOUR_API_KEY_HERE"}"#;
    let evals = evaluate_secret_candidates(dummy_text);
    assert!(!evals.is_empty());
    assert!(
        evals.iter().all(|e| !e.is_high_entropy),
        "Dummy placeholders must fail high-entropy gate"
    );

    let real_text = concat!(
        r#"{"aws_access_key_id": ""#,
        "AKIA",
        "9X4K2M8P3Q7R5T1W",
        r#""}"#
    );
    let real_evals = evaluate_secret_candidates(real_text);
    assert!(
        real_evals.iter().any(|e| e.is_high_entropy),
        "Real high-entropy AWS key must pass entropy gate"
    );
}

#[test]
fn test_dual_stage_ast_and_soft404_gates() {
    let rules = load_dorkset_csv(&dorkset_csv_path()).unwrap();

    // Baseline 404 page
    let html_404 = "<html><head><title>404 Not Found</title></head><body><div class='err'><h1>Page Not Found</h1><p>Not available</p></div></body></html>";
    let base_404_sim = dom_tag_simhash(html_404);
    assert_eq!(simhash_similarity_bps(base_404_sim, base_404_sim), 10000);

    // 1. False-positive directory listing (article mentioning "index of" without directory DOM)
    let fp_dir_html = "<html><head><title>Index of security guides</title></head><body><article><p>Read about configmap.yaml and smb.conf hardening.</p></article></body></html>";
    let fp_dir_doc = build_harvested_doc(
        "https://target.example/blog/index-of",
        200,
        "text/html",
        fp_dir_html,
    );

    // 2. True directory listing DOM
    let tp_dir_html = "<html><head><title>Index of /configs</title></head><body><h1>Index of /configs</h1><pre><a href=\"../\">Parent Directory</a>\n<a href=\"configmap.yaml\">configmap.yaml</a>\n<a href=\"proftpd.conf\">proftpd.conf</a></pre></body></html>";
    let tp_dir_doc = build_harvested_doc(
        "https://target.example/configs/",
        200,
        "text/html",
        tp_dir_html,
    );

    // 3. JS comment false positive (commented out aws_access_key_id)
    let js_fp = "// Note: aws_access_key_id should never be committed\nconsole.log('ready');";
    let stripped = strip_js_comments(js_fp);
    assert!(!stripped.contains("aws_access_key_id"));
    let js_fp_doc = build_harvested_doc(
        "https://target.example/app.js",
        200,
        "application/javascript",
        js_fp,
    );

    // 4. Low-entropy YAML honeypot
    let yaml_fp =
        "aws_access_key_id: AKIAXXXXXXXXXXXXXXXX\naws_secret_access_key: changeme123456\n";
    let yaml_fp_doc = build_harvested_doc(
        "https://target.example/secrets.yaml",
        200,
        "text/yaml",
        yaml_fp,
    );

    // 5. High-entropy YAML true exposure
    let yaml_tp = concat!("aws_access_key_id: ", "AKIA", "9X4K2M8P3Q7R5T1W\n");
    let yaml_tp_doc = build_harvested_doc(
        "https://target.example/prod.yaml",
        200,
        "text/yaml",
        yaml_tp,
    );

    // 6. True Login Portal DOM
    let login_tp = "<html><head><title>UAT Admin Login</title></head><body><form action=\"/auth/login\" method=\"post\"><input type=\"text\" name=\"user\"><input type=\"password\" name=\"pass\"></form></body></html>";
    let login_tp_doc = build_harvested_doc(
        "https://uat.target.example/login",
        200,
        "text/html",
        login_tp,
    );

    // 7. Soft-404 disguised as login URL
    let soft_404_doc = build_harvested_doc(
        "https://target.example/admin.php",
        200,
        "text/html",
        html_404,
    );

    let docs = vec![
        fp_dir_doc,
        tp_dir_doc,
        js_fp_doc,
        yaml_fp_doc,
        yaml_tp_doc,
        login_tp_doc,
        soft_404_doc,
    ];

    let (verified, stats) = verify_rules_against_docs(
        &rules,
        &docs,
        "https://target.example/",
        base_404_sim,
        false,
    );

    assert!(
        stats.ast_fp_dropped >= 1,
        "Expected AST FP drops >= 1, got {}",
        stats.ast_fp_dropped
    );
    assert!(
        stats.entropy_fp_dropped >= 1,
        "Expected Entropy FP drops >= 1, got {}",
        stats.entropy_fp_dropped
    );
    assert!(
        stats.soft404_fp_dropped >= 1,
        "Expected Soft-404 FP drops >= 1, got {}",
        stats.soft404_fp_dropped
    );

    assert!(
        verified.iter().any(|v| v.matched_endpoint.contains("/configs/") && v.ast_node_type == "DOM_DIR_INDEX"),
        "Expected verified directory index finding"
    );
    assert!(
        verified
            .iter()
            .any(|v| v.matched_endpoint.contains("/prod.yaml") && v.shannon_entropy_bps >= 300),
        "Expected verified high-entropy YAML finding"
    );
    assert!(
        verified
            .iter()
            .any(|v| v.matched_endpoint.contains("/login") && v.ast_node_type == "DOM_LOGIN_FORM"),
        "Expected verified login portal finding"
    );
    assert!(
        !verified
            .iter()
            .any(|v| v.matched_endpoint.contains("secrets.yaml")),
        "Low-entropy honeypot secrets.yaml must be suppressed in normal mode"
    );
    assert!(
        !verified
            .iter()
            .any(|v| v.matched_endpoint.contains("/blog/index-of")),
        "Blog article with 'index of' must be suppressed by Gate 1 AST"
    );
}

#[test]
fn test_sqlite_wal_ingest_roundtrip() {
    let rules = load_dorkset_csv(&dorkset_csv_path()).unwrap();
    let tmp_db = std::env::temp_dir().join(format!("autodorker_test_{}.db", std::process::id()));
    let tmp_str = tmp_db.to_string_lossy().to_string();

    let mut conn = open_wal_db(&tmp_str).expect("Open WAL SQLite DB");
    let count = ingest_dork_catalog(&mut conn, &rules).expect("Ingest catalog");
    assert_eq!(count, 295);

    let reloaded = load_catalog_rules(&conn).expect("Reload catalog");
    assert_eq!(reloaded.len(), 295);
    assert!(matches!(
        reloaded[0].expr_tree,
        DorkExpr::And(_) | DorkExpr::Or(_) | DorkExpr::Term(DorkOperator::InUrl(_)) | _
    ));

    let _ = std::fs::remove_file(&tmp_db);
    let _ = std::fs::remove_file(format!("{}-wal", tmp_str));
    let _ = std::fs::remove_file(format!("{}-shm", tmp_str));
}
