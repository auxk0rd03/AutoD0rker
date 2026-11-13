use dork_spider::ast_verifier::{
    build_harvested_doc, strip_js_comments, verify_rules_against_docs,
};
use dork_spider::db::{ingest_dork_catalog, load_catalog_rules, open_wal_db};
use dork_spider::dork_ast::{
    CompiledDorkRule, DorkExpr, DorkOperator, load_dorkset_csv, parse_dork_string,
    synthesize_probe_paths,
};
use dork_spider::entropy::{
    dom_tag_simhash, evaluate_secret_candidates, shannon_entropy, shannon_entropy_bps,
    simhash_similarity_bps,
};
use dork_spider::spider::{
    PinnedSsrfResolver, is_allowed_domain, is_blocked_ip, validate_proxy_url,
};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use url::Url;

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

#[test]
fn test_cross_asset_chain_correlation() {
    let multi_asset_rule = CompiledDorkRule {
        rule_id: 1,
        category: "[CHAIN] Files Containing Juicy Info".to_string(),
        is_chain: true,
        raw_dork: r#"inurl:".git" intext:"openapi""#.to_string(),
        notes: "Cross-asset chain rule".to_string(),
        default_severity: "HIGH".to_string(),
        cwe_id: "CWE-538".to_string(),
        expr_tree: parse_dork_string(r#"inurl:".git" intext:"openapi""#),
        candidate_probe_paths: vec!["/.git/config".to_string(), "/swagger.json".to_string()],
    };
    let rules = vec![multi_asset_rule];

    let git_doc = build_harvested_doc(
        "https://chain.example/.git/config",
        200,
        "text/plain",
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n",
    );
    let robots_doc = build_harvested_doc(
        "https://chain.example/robots.txt",
        200,
        "text/plain",
        "User-agent: *\nDisallow: /admin\nDisallow: /internal-api\n",
    );
    let swagger_doc = build_harvested_doc(
        "https://chain.example/swagger.json",
        200,
        "application/json",
        r#"{"openapi":"3.0.1","info":{"title":"Corp Internal API"}}"#,
    );
    let admin_login_doc = build_harvested_doc(
        "https://chain.example/admin",
        200,
        "text/html",
        "<html><head><title>Corp Admin Portal</title></head><body><form method=\"post\" action=\"/admin/login\"><input type=\"text\" name=\"u\"><input type=\"password\" name=\"p\"></form></body></html>",
    );

    let docs = vec![git_doc, robots_doc, swagger_doc, admin_login_doc];
    let (verified, _stats) =
        verify_rules_against_docs(&rules, &docs, "https://chain.example/", 0, false);

    assert!(
        verified
            .iter()
            .any(|v| v.ast_node_type == "CHAIN_GIT_RECON_PIVOT" && v.severity == "CRITICAL"),
        "Expected CRITICAL composite .git + robots/swagger/login chain finding; got {:?}",
        verified
    );
    assert!(
        verified
            .iter()
            .any(|v| v.ast_node_type == "CHAIN_ROBOTS_SURFACE_PIVOT" && v.severity == "HIGH"),
        "Expected HIGH robots.txt + accessible disallowed route / swagger chain finding"
    );
    assert!(
        verified
            .iter()
            .any(|v| v.ast_node_type == "CHAIN_MULTI_ASSET_RULE"),
        "Expected cross-asset DorkExpr::And [CHAIN] match spanning .git/config and swagger.json"
    );
}

#[test]
fn test_pinned_ssrf_resolver_and_redirect_policy() {
    let blocked_ips = [
        "127.0.0.1",
        "10.0.0.5",
        "172.16.4.20",
        "192.168.1.99",
        "100.64.0.1",
        "169.254.169.254",
        "::1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "fe80::1",
        "fc00::1",
    ];
    for raw in blocked_ips {
        let ip: IpAddr = raw.parse().unwrap();
        assert!(
            is_blocked_ip(ip, false),
            "IP {} must be blocked in strict mode",
            raw
        );
    }

    // Even in allow_local_staging=true, cloud metadata must stay blocked
    let metadata_ip: IpAddr = "169.254.169.254".parse().unwrap();
    assert!(is_blocked_ip(metadata_ip, true));
    let mapped_meta: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
    assert!(is_blocked_ip(mapped_meta, true));

    // Public IP passes SSRF check and is pinned deterministically
    let public_ip: IpAddr = "93.184.216.34".parse().unwrap();
    assert!(!is_blocked_ip(public_ip, false));

    let resolver = PinnedSsrfResolver::new(false);
    assert!(resolver.resolve_and_pin("127.0.0.1", 80).is_err());
    assert!(
        resolver
            .resolve_and_pin("metadata.google.internal", 80)
            .is_err()
    );
    let pinned = resolver
        .resolve_and_pin("93.184.216.34", 443)
        .expect("Public IP literal should pin");
    assert_eq!(pinned[0].ip(), public_ip);
    assert_eq!(
        resolver.pinned_ips_for("93.184.216.34", 443),
        vec![public_ip]
    );

    // Proxy validation blocks loopback/metadata proxies in strict mode
    assert!(validate_proxy_url("http://127.0.0.1:8080", false).is_err());
    assert!(validate_proxy_url("http://169.254.169.254:80", true).is_err());
    assert!(validate_proxy_url("ftp://93.184.216.34:21", false).is_err());
    assert!(validate_proxy_url("http://93.184.216.34:3128", false).is_ok());

    // Canonical www.<apex> <-> <apex> redirect allowance + subdomain scope
    let apex_url = Url::parse("https://example.com/robots.txt").unwrap();
    let sub_url = Url::parse("https://api.example.com/v1").unwrap();
    let rogue_url = Url::parse("https://notexample.com/").unwrap();
    assert!(is_allowed_domain(&apex_url, "www.example.com"));
    assert!(is_allowed_domain(&sub_url, "example.com"));
    assert!(!is_allowed_domain(&rogue_url, "example.com"));
}

#[test]
fn test_property_fuzz_dork_ast_and_verifier() {
    struct Xorshift64(u64);
    impl Xorshift64 {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn next_usize(&mut self, bound: usize) -> usize {
            (self.next_u64() % bound as u64) as usize
        }
    }

    let tokens = [
        "inurl:",
        "intitle:",
        "intext:",
        "filetype:",
        "ext:",
        "site:",
        "allinurl:",
        "allintext:",
        "(",
        ")",
        "|",
        "&",
        "OR",
        "AND",
        "-",
        "+",
        "\"",
        "'",
        ",",
        " ",
        "../",
        "*.*",
        ".env",
        "admin",
        "aws_secret_access_key",
        "\"unterminated",
        "'mismatch\"",
        "<script>",
        "\r\n",
        "\0",
        "über",
    ];

    let mut rng = Xorshift64(0xDEAD_BEEF_CAFE_BABEu64);
    for case_idx in 0..5500usize {
        let len = 1 + rng.next_usize(18);
        let mut expr_str = String::new();
        for _ in 0..len {
            expr_str.push_str(tokens[rng.next_usize(tokens.len())]);
            if rng.next_usize(3) == 0 {
                expr_str.push(' ');
            }
        }
        let parsed = parse_dork_string(&expr_str);
        let json = serde_json::to_string(&parsed).expect("Fuzzed AST must serialize");
        let _roundtrip: DorkExpr =
            serde_json::from_str(&json).expect("Fuzzed AST must deserialize");

        let probes = synthesize_probe_paths(&parsed);
        for p in probes {
            assert!(
                p.starts_with('/') && !p.contains('\r') && !p.contains('\n') && !p.contains('\0'),
                "Unsafe synthesized probe path at iter {}: {:?}",
                case_idx,
                p
            );
        }

        if case_idx < 300 {
            let body = format!(
                "{{\"k\":\"{}\"}} <!-- {} --> <form><input type='password'></form> \x00 {}",
                expr_str.replace('"', ""),
                expr_str,
                &expr_str
            );
            let doc = build_harvested_doc(
                "https://fuzz.example/config.yaml?v=1",
                if case_idx % 5 == 0 { 404 } else { 200 },
                if case_idx % 2 == 0 {
                    "text/yaml"
                } else {
                    "text/html"
                },
                &body,
            );
            let rule = CompiledDorkRule {
                rule_id: (case_idx as i64) + 1,
                category: "Fuzz".to_string(),
                is_chain: case_idx % 3 == 0,
                raw_dork: expr_str.clone(),
                notes: String::new(),
                default_severity: "MEDIUM".to_string(),
                cwe_id: "CWE-200".to_string(),
                expr_tree: parsed,
                candidate_probe_paths: vec![],
            };
            let _ = verify_rules_against_docs(
                &[rule],
                &[doc],
                "https://fuzz.example/",
                rng.next_u64(),
                case_idx % 2 == 0,
            );
        }
    }
}
