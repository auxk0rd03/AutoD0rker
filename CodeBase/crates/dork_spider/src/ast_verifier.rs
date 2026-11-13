use crate::dork_ast::{CompiledDorkRule, DorkExpr, DorkOperator};
use crate::entropy::{
    dom_tag_simhash, evaluate_secret_candidates, shannon_entropy_bps, simhash_similarity_bps,
};
use regex::Regex;
use scraper::{Html, Selector};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocKind {
    Html,
    JavaScript,
    Json,
    Yaml,
    Config,
    Sql,
    Log,
    Text,
}

#[derive(Debug, Clone)]
pub struct HarvestedDoc {
    pub url: String,
    pub path: String,
    pub host: String,
    pub status_code: u16,
    pub content_type: String,
    pub raw_body: String,
    pub doc_kind: DocKind,
    pub html_title: String,
    pub html_visible_text: String,
    pub has_dir_index_dom: bool,
    pub has_login_dom: bool,
    pub dir_listing_entries: Vec<String>,
    pub outbound_links: Vec<String>,
    pub js_uncommented: String,
    pub js_assigned_values: Vec<(String, String)>,
    pub config_valid: bool,
    pub simhash: u64,
    pub body_entropy_bps: i64,
    pub is_vendor_asset: bool,
    pub robots_disallowed: Vec<String>,
    pub is_git_exposed: bool,
    pub is_swagger_exposed: bool,
}

#[derive(Debug, Clone)]
pub struct VerifiedMatch {
    pub rule_id: i64,
    pub category: String,
    pub is_chain: bool,
    pub raw_dork: String,
    pub severity: String,
    pub cwe_id: String,
    pub cvss_vector: String,
    pub cvss_score_bps: i64,
    pub matched_endpoint: String,
    pub ast_node_type: String,
    pub ast_context_snippet: String,
    pub shannon_entropy_bps: i64,
    pub confidence_bps: i64,
    pub is_vendor_observation: bool,
    pub is_shadow_downgraded: bool,
}

#[derive(Debug, Default, Clone)]
pub struct VerificationStats {
    pub raw_candidates: i64,
    pub ast_fp_dropped: i64,
    pub soft404_fp_dropped: i64,
    pub entropy_fp_dropped: i64,
}

const VENDOR_PATTERNS: &[&str] = &[
    "akamai",
    "tiqcdn",
    "tealium",
    "adobe",
    "demdex",
    "google-analytics",
    "googletagmanager",
    "doubleclick",
];

pub fn is_vendor_url(url_or_path: &str) -> bool {
    let lower = url_or_path.to_ascii_lowercase();
    VENDOR_PATTERNS.iter().any(|p| lower.contains(p))
}

pub fn infer_doc_kind(url_path: &str, content_type: &str, body: &str) -> DocKind {
    let lower_path = url_path
        .split('?')
        .next()
        .unwrap_or(url_path)
        .to_ascii_lowercase();
    let lower_ct = content_type.to_ascii_lowercase();
    let trimmed = body.trim_start();

    if lower_path.ends_with(".js")
        || lower_path.ends_with(".mjs")
        || lower_ct.contains("javascript")
    {
        return DocKind::JavaScript;
    }
    if lower_path.ends_with(".json") || lower_ct.contains("application/json") {
        return DocKind::Json;
    }
    if lower_path.ends_with(".yaml") || lower_path.ends_with(".yml") || lower_ct.contains("yaml") {
        return DocKind::Yaml;
    }
    if lower_path.ends_with(".sql") || lower_ct.contains("sql") {
        return DocKind::Sql;
    }
    if lower_path.ends_with(".log") {
        return DocKind::Log;
    }
    if lower_path.ends_with(".env")
        || lower_path.ends_with(".conf")
        || lower_path.ends_with(".properties")
        || lower_path.ends_with(".ini")
        || lower_path.ends_with(".config")
        || lower_path.ends_with(".xml")
        || lower_path.ends_with(".neon")
        || lower_path.ends_with(".nix")
    {
        return DocKind::Config;
    }
    if lower_ct.contains("text/html")
        || lower_path.ends_with(".html")
        || lower_path.ends_with(".htm")
        || lower_path.ends_with(".php")
        || lower_path.ends_with(".aspx")
        || lower_path.ends_with(".jsp")
        || trimmed.starts_with("<!DOCTYPE")
        || trimmed.starts_with("<!doctype")
        || trimmed.starts_with("<html")
    {
        return DocKind::Html;
    }
    DocKind::Text
}

/// Strips `//` line comments and `/* ... */` block comments from JS without corrupting string literals.
pub fn strip_js_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let chars: Vec<char> = src.chars().collect();
    let mut i = 0;
    let mut in_quote: Option<char> = None;

    while i < chars.len() {
        let ch = chars[i];
        if let Some(q) = in_quote {
            out.push(ch);
            if ch == '\\' && i + 1 < chars.len() {
                i += 1;
                out.push(chars[i]);
            } else if ch == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }

        if ch == '"' || ch == '\'' || ch == '`' {
            in_quote = Some(ch);
            out.push(ch);
            i += 1;
            continue;
        }

        if ch == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
            i += 2;
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            out.push('\n');
            continue;
        }

        if ch == '/' && i + 1 < chars.len() && chars[i + 1] == '*' {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i = (i + 2).min(chars.len());
            out.push(' ');
            continue;
        }

        out.push(ch);
        i += 1;
    }
    out
}

fn extract_js_assignments(js_uncommented: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let re = Regex::new(r#"(?i)([A-Za-z_][A-Za-z0-9_]{2,48})\s*[:=]\s*["']([^"'\r\n]{4,160})["']"#)
        .unwrap();
    for cap in re.captures_iter(js_uncommented) {
        if let (Some(k), Some(v)) = (cap.get(1), cap.get(2)) {
            pairs.push((k.as_str().to_string(), v.as_str().to_string()));
        }
    }
    pairs
}

fn verify_config_structure(kind: &DocKind, body: &str) -> bool {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    // Reject HTML soft-404 disguised as config/JSON/YAML/SQL
    if lower.starts_with("<!doctype html") || lower.starts_with("<html") || lower.contains("<body")
    {
        return false;
    }
    match kind {
        DocKind::Json => serde_json::from_str::<serde_json::Value>(trimmed).is_ok(),
        DocKind::Yaml => trimmed.lines().any(|line| {
            let l = line.trim();
            !l.is_empty() && !l.starts_with('#') && l.contains(':')
        }),
        DocKind::Sql => {
            lower.contains("create table")
                || lower.contains("insert into")
                || lower.contains("phpmyadmin")
                || lower.contains("mysqldump")
                || lower.contains("pg_dump")
        }
        DocKind::Config => trimmed.lines().any(|line| {
            let l = line.trim();
            !l.is_empty()
                && !l.starts_with('#')
                && (l.contains('=')
                    || l.contains(':')
                    || l.starts_with('<')
                    || l.contains("ServerName")
                    || l.contains("BEGIN "))
        }),
        DocKind::Log => trimmed.lines().any(|l| {
            l.contains('[')
                || l.contains("ERROR")
                || l.contains("FATAL")
                || l.contains("Header for logs")
                || l.contains("START ")
        }),
        _ => true,
    }
}

pub fn build_harvested_doc(
    url: &str,
    status_code: u16,
    content_type: &str,
    raw_body: &str,
) -> HarvestedDoc {
    let parsed = url::Url::parse(url).ok();
    let host = parsed
        .as_ref()
        .and_then(|u| u.host_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let path = parsed
        .as_ref()
        .map(|u| match u.query() {
            Some(q) => format!("{}?{}", u.path(), q),
            None => u.path().to_string(),
        })
        .unwrap_or_else(|| "/".to_string());

    let doc_kind = infer_doc_kind(&path, content_type, raw_body);
    let simhash = dom_tag_simhash(raw_body);
    let body_entropy_bps = shannon_entropy_bps(raw_body);

    let mut html_title = String::new();
    let mut html_visible_text = String::new();
    let mut has_dir_index_dom = false;
    let mut has_login_dom = false;
    let mut dir_listing_entries = Vec::new();
    let mut outbound_links = Vec::new();

    if doc_kind == DocKind::Html {
        let document = Html::parse_document(raw_body);
        if let Ok(title_sel) = Selector::parse("head title, title") {
            if let Some(el) = document.select(&title_sel).next() {
                html_title = el.text().collect::<Vec<_>>().join(" ").trim().to_string();
            }
        }

        // Visible text excluding script/style tags
        if let Ok(body_sel) = Selector::parse("body") {
            if let Some(body_el) = document.select(&body_sel).next() {
                let raw_text = body_el.text().collect::<Vec<_>>().join(" ");
                html_visible_text = raw_text.split_whitespace().collect::<Vec<_>>().join(" ");
            }
        }
        if html_visible_text.is_empty() {
            html_visible_text = document.root_element().text().collect::<Vec<_>>().join(" ");
        }

        // Structural Login Portal AST verification
        let pw_sel = Selector::parse("input[type='password'], input[type=\"password\"]").unwrap();
        let form_sel = Selector::parse("form").unwrap();
        let a_sel = Selector::parse("a[href]").unwrap();
        let script_sel = Selector::parse("script[src]").unwrap();

        let has_pw_input = document.select(&pw_sel).next().is_some();
        let has_auth_form = document.select(&form_sel).any(|f| {
            let action = f.value().attr("action").unwrap_or("").to_ascii_lowercase();
            let id = f.value().attr("id").unwrap_or("").to_ascii_lowercase();
            let name = f.value().attr("name").unwrap_or("").to_ascii_lowercase();
            let cls = f.value().attr("class").unwrap_or("").to_ascii_lowercase();
            [action, id, name, cls].iter().any(|s| {
                s.contains("login")
                    || s.contains("signin")
                    || s.contains("sign-in")
                    || s.contains("auth")
                    || s.contains("sso")
                    || s.contains("oauth")
                    || s.contains("saml")
            })
        });
        let has_oauth_link = document.select(&a_sel).any(|a| {
            let href = a.value().attr("href").unwrap_or("").to_ascii_lowercase();
            href.contains("oauth")
                || href.contains("saml")
                || href.contains("/adfs/ls")
                || href.contains("/cas/login")
        });
        has_login_dom = has_pw_input || has_auth_form || has_oauth_link;

        // Collect links & structural Directory Index AST verification
        let pre_or_table_a_sel =
            Selector::parse("pre a[href], table a[href], ul li a[href]").unwrap();
        for a in document.select(&a_sel) {
            if let Some(href) = a.value().attr("href") {
                outbound_links.push(href.to_string());
            }
        }
        for s in document.select(&script_sel) {
            if let Some(src) = s.value().attr("src") {
                outbound_links.push(src.to_string());
            }
        }

        let title_has_index_of = html_title.to_ascii_lowercase().contains("index of");
        let listing_anchors: Vec<(String, String)> = document
            .select(&pre_or_table_a_sel)
            .filter_map(|a| {
                let href = a.value().attr("href")?.to_string();
                let txt = a.text().collect::<Vec<_>>().join("").trim().to_string();
                Some((href, txt))
            })
            .collect();

        let has_index_markers = listing_anchors.iter().any(|(href, txt)| {
            let hl = href.to_ascii_lowercase();
            let tl = txt.to_ascii_lowercase();
            hl == "../"
                || hl.starts_with("?c=")
                || tl.contains("parent directory")
                || tl == "name"
                || hl.ends_with(".conf")
                || hl.ends_with(".yaml")
                || hl.ends_with(".yml")
                || hl.ends_with(".sql")
                || hl.ends_with(".env")
                || hl.ends_with(".log")
                || hl.ends_with(".txt")
                || hl.ends_with(".json")
                || hl.ends_with(".zip")
        });

        if title_has_index_of && (!listing_anchors.is_empty() && has_index_markers) {
            has_dir_index_dom = true;
            for (href, txt) in listing_anchors {
                if !href.starts_with("?C=") && href != "../" {
                    dir_listing_entries.push(format!("{} {}", href, txt));
                }
            }
        }
    }

    let (js_uncommented, js_assigned_values) = if doc_kind == DocKind::JavaScript {
        let stripped = strip_js_comments(raw_body);
        let assigns = extract_js_assignments(&stripped);
        (stripped, assigns)
    } else {
        (String::new(), Vec::new())
    };

    let config_valid = verify_config_structure(&doc_kind, raw_body);

    let lower_path = path.split('?').next().unwrap_or(&path).to_ascii_lowercase();
    let lower_body = raw_body.to_ascii_lowercase();
    let mut robots_disallowed = Vec::new();
    if lower_path == "/robots.txt" && status_code == 200 {
        for line in raw_body.lines() {
            let trimmed = line.split('#').next().unwrap_or("").trim();
            if let Some(rest) = trimmed
                .strip_prefix("Disallow:")
                .or_else(|| trimmed.strip_prefix("disallow:"))
            {
                let rpath = rest.trim();
                if rpath.starts_with('/') && rpath != "/" {
                    robots_disallowed.push(rpath.to_string());
                }
            }
        }
    }

    let is_git_exposed = status_code == 200
        && ((lower_path.contains("/.git/")
            && (lower_body.contains("[core]")
                || lower_body.contains("[remote ")
                || lower_body.contains("ref: refs/")))
            || (has_dir_index_dom
                && dir_listing_entries
                    .iter()
                    .any(|e| e.to_ascii_lowercase().contains(".git"))));

    let is_swagger_exposed = status_code == 200
        && !lower_body.starts_with("<!doctype html><html><head><title>404")
        && (lower_path.contains("swagger")
            || lower_path.contains("api-docs")
            || lower_path.contains("openapi"))
        && (matches!(doc_kind, DocKind::Json | DocKind::Yaml)
            || lower_body.contains("swagger-ui")
            || lower_body.contains("\"openapi\"")
            || lower_body.contains("\"swagger\""));

    HarvestedDoc {
        url: url.to_string(),
        path,
        host,
        status_code,
        content_type: content_type.to_string(),
        raw_body: raw_body.to_string(),
        doc_kind,
        html_title,
        html_visible_text,
        has_dir_index_dom,
        has_login_dom,
        dir_listing_entries,
        outbound_links,
        js_uncommented,
        js_assigned_values,
        config_valid,
        simhash,
        body_entropy_bps,
        is_vendor_asset: is_vendor_url(url),
        robots_disallowed,
        is_git_exposed,
        is_swagger_exposed,
    }
}

fn wildcard_contains(haystack: &str, pattern: &str) -> bool {
    let h = haystack.to_ascii_lowercase();
    let p = pattern.trim().to_ascii_lowercase();
    if p.is_empty() {
        return false;
    }
    if !p.contains('*') {
        return h.contains(&p);
    }
    let parts: Vec<&str> = p.split('*').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return true;
    }
    let mut pos = 0usize;
    for part in parts {
        if let Some(found) = h[pos..].find(part) {
            pos += found + part.len();
        } else {
            return false;
        }
    }
    true
}

fn match_site_pattern(doc: &HarvestedDoc, pat: &str) -> bool {
    let p = pat.trim().trim_start_matches('.').to_ascii_lowercase();
    if p.is_empty() || p == "*.*" || p == "*" {
        return true;
    }
    let host = &doc.host;
    if p.contains('*') {
        if wildcard_contains(host, &p) {
            return true;
        }
        return doc.outbound_links.iter().any(|l| wildcard_contains(l, &p));
    }
    if host == &p || host.ends_with(&format!(".{}", p)) {
        return true;
    }
    // Local translation of third-party site: directives (e.g. site:github.com)
    doc.outbound_links
        .iter()
        .any(|l| l.to_ascii_lowercase().contains(&p))
}

fn match_filetype(doc: &HarvestedDoc, ext: &str) -> bool {
    let e = ext.trim().trim_start_matches('.').to_ascii_lowercase();
    if e.is_empty() {
        return false;
    }
    let path_clean = doc
        .path
        .split('?')
        .next()
        .unwrap_or(&doc.path)
        .to_ascii_lowercase();
    let matches_ext = |p: &str| -> bool {
        if e == "yaml" || e == "yml" {
            p.ends_with(".yaml") || p.ends_with(".yml")
        } else {
            p.ends_with(&format!(".{}", e))
        }
    };
    if matches_ext(&path_clean) {
        return true;
    }
    if doc.doc_kind == DocKind::Json && e == "json" {
        return true;
    }
    if doc.doc_kind == DocKind::Yaml && (e == "yaml" || e == "yml") {
        return true;
    }
    if doc.doc_kind == DocKind::Sql && e == "sql" {
        return true;
    }
    if doc.doc_kind == DocKind::Log && e == "log" {
        return true;
    }
    if doc.has_dir_index_dom {
        return doc
            .dir_listing_entries
            .iter()
            .any(|entry| matches_ext(&entry.to_ascii_lowercase()));
    }
    false
}

fn match_operator(op: &DorkOperator, doc: &HarvestedDoc) -> bool {
    match op {
        DorkOperator::InUrl(val) => {
            if wildcard_contains(&doc.path, val) || wildcard_contains(&doc.url, val) {
                return true;
            }
            if doc.has_dir_index_dom {
                return doc
                    .dir_listing_entries
                    .iter()
                    .any(|e| wildcard_contains(e, val));
            }
            false
        }
        DorkOperator::InTitle(val) => {
            let v_lower = val.to_ascii_lowercase();
            let title_lower = doc.html_title.to_ascii_lowercase();
            if v_lower.starts_with("index of /") {
                let sub = v_lower.trim_start_matches("index of").trim();
                title_lower.contains("index of")
                    && (title_lower.contains(sub) || doc.path.to_ascii_lowercase().contains(sub))
            } else {
                wildcard_contains(&doc.html_title, val)
            }
        }
        DorkOperator::InText(val) => match doc.doc_kind {
            DocKind::Html => {
                wildcard_contains(&doc.html_visible_text, val)
                    || doc
                        .dir_listing_entries
                        .iter()
                        .any(|e| wildcard_contains(e, val))
            }
            DocKind::JavaScript => wildcard_contains(&doc.js_uncommented, val),
            _ => wildcard_contains(&doc.raw_body, val),
        },
        DorkOperator::FileType(ext) => match_filetype(doc, ext),
        DorkOperator::Site(pat) => match_site_pattern(doc, pat),
        DorkOperator::ExactPhrase(val) => {
            if val.trim().is_empty() {
                return false;
            }
            match doc.doc_kind {
                DocKind::Html => {
                    wildcard_contains(&doc.html_title, val)
                        || wildcard_contains(&doc.html_visible_text, val)
                        || doc
                            .dir_listing_entries
                            .iter()
                            .any(|e| wildcard_contains(e, val))
                }
                DocKind::JavaScript => wildcard_contains(&doc.js_uncommented, val),
                _ => wildcard_contains(&doc.raw_body, val),
            }
        }
    }
}

pub fn eval_dork_expr(expr: &DorkExpr, doc: &HarvestedDoc) -> bool {
    match expr {
        DorkExpr::Term(op) => match_operator(op, doc),
        DorkExpr::Not(inner) => !eval_dork_expr(inner, doc),
        DorkExpr::And(list) => list.iter().all(|e| eval_dork_expr(e, doc)),
        DorkExpr::Or(list) => list.iter().any(|e| eval_dork_expr(e, doc)),
    }
}

fn rule_requires_dir_index(rule: &CompiledDorkRule) -> bool {
    let lower = rule.raw_dork.to_ascii_lowercase();
    lower.contains("intitle:\"index of\"")
        || lower.contains("intitle: \"index of\"")
        || lower.contains("intitle:index of")
        || lower.contains("intitle:index.of")
        || lower.contains("index of:")
        || lower.contains("indexof:")
}

fn rule_is_login_portal(rule: &CompiledDorkRule) -> bool {
    rule.category.to_ascii_lowercase().contains("login portals")
}

fn rule_is_secret_sensitive(rule: &CompiledDorkRule) -> bool {
    let cat = rule.category.to_ascii_lowercase();
    let dork = rule.raw_dork.to_ascii_lowercase();
    cat.contains("passwords")
        || dork.contains("aws_access_key_id")
        || dork.contains("aws_secret_access_key")
        || dork.contains("begin openssh private key")
        || dork.contains("access_token.json")
        || dork.contains("secret.txt")
        || dork.contains("creds.txt")
        || dork.contains("pass.txt")
        || dork.contains("private_key.pem")
        || dork.contains(".env")
}

fn map_cvss(severity: &str, cwe_id: &str) -> (&'static str, i64) {
    match (severity, cwe_id) {
        ("CRITICAL", _) => ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 910),
        ("HIGH", "CWE-538") => ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 750),
        ("HIGH", _) => ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 750),
        ("MEDIUM", "CWE-287") => ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", 650),
        ("MEDIUM", _) => ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 530),
        ("LOW", _) => ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 370),
        _ => ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0),
    }
}

fn extract_snippet(doc: &HarvestedDoc, needle_hint: &str) -> String {
    let source = match doc.doc_kind {
        DocKind::JavaScript => &doc.js_uncommented,
        _ => &doc.raw_body,
    };
    let lower_src = source.to_ascii_lowercase();
    let lower_hint = needle_hint.to_ascii_lowercase();
    let snippet = if !lower_hint.is_empty() {
        if let Some(pos) = lower_src.find(&lower_hint) {
            let start = source[..pos]
                .char_indices()
                .rev()
                .nth(40)
                .map(|(i, _)| i)
                .unwrap_or(0);
            let end = source[pos..]
                .char_indices()
                .nth(140)
                .map(|(i, _)| pos + i)
                .unwrap_or(source.len());
            source[start..end].trim().to_string()
        } else {
            source.chars().take(180).collect()
        }
    } else {
        source.chars().take(180).collect()
    };
    snippet.replace(['\r', '\n'], " ")
}

/// Runs the Dual-Stage False-Positive Reduction pipeline (Dork AST + Gate 1 Source AST + Gate 2 Shannon Entropy).
pub fn verify_rules_against_docs(
    rules: &[CompiledDorkRule],
    docs: &[HarvestedDoc],
    root_url: &str,
    baseline_404_simhash: u64,
    shadow_mode: bool,
) -> (Vec<VerifiedMatch>, VerificationStats) {
    let mut verified = Vec::new();
    let mut stats = VerificationStats::default();
    let mut dedup: HashSet<(i64, String)> = HashSet::new();
    let mut valid_docs: Vec<&HarvestedDoc> = Vec::new();

    for doc in docs {
        // Gate 0: Soft-404 Differential SimHash Guard (Section 3.4A)
        if doc.url != root_url && baseline_404_simhash != 0 {
            let sim = simhash_similarity_bps(doc.simhash, baseline_404_simhash);
            if sim > 9200 {
                stats.soft404_fp_dropped += 1;
                continue;
            }
        }
        // Reject disguised HTML soft-404 on structured file paths
        if matches!(
            doc.doc_kind,
            DocKind::Json | DocKind::Yaml | DocKind::Config | DocKind::Sql
        ) && !doc.config_valid
        {
            stats.soft404_fp_dropped += 1;
            continue;
        }
        valid_docs.push(doc);

        for rule in rules {
            if !eval_dork_expr(&rule.expr_tree, doc) {
                continue;
            }
            stats.raw_candidates += 1;

            // Gate 1A: Directory Listing DOM AST verification
            if rule_requires_dir_index(rule) && !doc.has_dir_index_dom {
                stats.ast_fp_dropped += 1;
                continue;
            }

            // Gate 1B: Login Portal DOM AST verification (<input type="password"> or auth <form>/SSO)
            if rule_is_login_portal(rule) && !doc.has_login_dom {
                stats.ast_fp_dropped += 1;
                continue;
            }

            // Gate 1C: JS Assignment / Config AST verification
            if doc.doc_kind == DocKind::JavaScript && rule_is_secret_sensitive(rule) {
                let has_assignment = doc.js_assigned_values.iter().any(|(k, _)| {
                    let kl = k.to_ascii_lowercase();
                    kl.contains("aws")
                        || kl.contains("key")
                        || kl.contains("secret")
                        || kl.contains("token")
                        || kl.contains("pass")
                });
                if !has_assignment && !doc.js_uncommented.contains("BEGIN OPENSSH PRIVATE KEY") {
                    stats.ast_fp_dropped += 1;
                    continue;
                }
            }

            // Gate 2: Shannon Entropy Evaluation H(X) for secrets/credentials
            let mut ast_node_type = match doc.doc_kind {
                DocKind::Html if rule_requires_dir_index(rule) => "DOM_DIR_INDEX",
                DocKind::Html if rule_is_login_portal(rule) => "DOM_LOGIN_FORM",
                DocKind::Html => "DOM_TITLE",
                DocKind::JavaScript => "JS_OBJ_PROP",
                DocKind::Yaml => "YAML_KEY",
                DocKind::Json => "JSON_KEY",
                DocKind::Sql => "SQL_DUMP",
                DocKind::Config => "CONFIG_KV",
                DocKind::Log => "LOG_STREAM",
                DocKind::Text => "TEXT_DOC",
            }
            .to_string();

            let mut severity = rule.default_severity.clone();
            let mut confidence_bps: i64 = 9000;
            let mut entropy_bps = doc.body_entropy_bps;
            let mut snippet = if doc.has_dir_index_dom {
                format!(
                    "<title>{}</title> | entries: {}",
                    doc.html_title,
                    doc.dir_listing_entries
                        .iter()
                        .take(5)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            } else if doc.has_login_dom && rule_is_login_portal(rule) {
                format!(
                    "<title>{}</title> | verified <form>/<input type='password'>",
                    doc.html_title
                )
            } else {
                extract_snippet(doc, "")
            };
            let mut shadow_downgraded = false;

            if rule_is_secret_sensitive(rule) {
                let candidates = evaluate_secret_candidates(&doc.raw_body);
                if !candidates.is_empty() {
                    if let Some(best) = candidates
                        .iter()
                        .filter(|c| c.is_high_entropy)
                        .max_by_key(|c| c.entropy_bps)
                    {
                        entropy_bps = best.entropy_bps;
                        confidence_bps = 9600;
                        snippet = format!("{}={}", best.matched_key, best.redacted_value);
                        if doc.doc_kind == DocKind::JavaScript {
                            ast_node_type = "JS_SECRET_ASSIGN".to_string();
                        } else if doc.doc_kind == DocKind::Yaml {
                            ast_node_type = "YAML_SECRET_KEY".to_string();
                        } else if doc.doc_kind == DocKind::Json {
                            ast_node_type = "JSON_SECRET_KEY".to_string();
                        }
                    } else {
                        // All extracted candidate tokens are low-entropy / dummy placeholders
                        let max_low = candidates.iter().map(|c| c.entropy_bps).max().unwrap_or(0);
                        if !shadow_mode {
                            stats.entropy_fp_dropped += 1;
                            continue;
                        }
                        entropy_bps = max_low;
                        severity = "INFO".to_string();
                        confidence_bps = 4500;
                        shadow_downgraded = true;
                        snippet = format!(
                            "[SHADOW_MODE: LOW_ENTROPY_PLACEHOLDER] {}={}",
                            candidates[0].matched_key, candidates[0].redacted_value
                        );
                    }
                } else if doc.raw_body.contains("aws_access_key_id")
                    && !doc.raw_body.contains("AKIA")
                {
                    // Mention of keyword without an assigned key structure -> drop in Gate 1/2
                    if !shadow_mode {
                        stats.ast_fp_dropped += 1;
                        continue;
                    }
                    severity = "INFO".to_string();
                    confidence_bps = 4000;
                    shadow_downgraded = true;
                }
            }

            if doc.is_vendor_asset {
                severity = "INFO".to_string();
            }

            if !dedup.insert((rule.rule_id, doc.url.clone())) {
                continue;
            }

            let (cvss_vector, cvss_score_bps) = map_cvss(&severity, &rule.cwe_id);
            verified.push(VerifiedMatch {
                rule_id: rule.rule_id,
                category: rule.category.clone(),
                is_chain: rule.is_chain,
                raw_dork: rule.raw_dork.clone(),
                severity,
                cwe_id: rule.cwe_id.clone(),
                cvss_vector: cvss_vector.to_string(),
                cvss_score_bps,
                matched_endpoint: doc.url.clone(),
                ast_node_type,
                ast_context_snippet: snippet,
                shannon_entropy_bps: entropy_bps,
                confidence_bps,
                is_vendor_observation: doc.is_vendor_asset,
                is_shadow_downgraded: shadow_downgraded,
            });
        }
    }

    correlate_chain_findings(rules, &valid_docs, &mut verified, &mut dedup);

    (verified, stats)
}

fn collect_and_branches<'a>(expr: &'a DorkExpr, out: &mut Vec<&'a DorkExpr>) {
    match expr {
        DorkExpr::And(parts) => {
            for part in parts {
                collect_and_branches(part, out);
            }
        }
        _ => out.push(expr),
    }
}

fn find_chain_anchor_rule<'a>(
    rules: &'a [CompiledDorkRule],
    preferred_terms: &[&str],
) -> Option<&'a CompiledDorkRule> {
    for term in preferred_terms {
        let needle = term.to_ascii_lowercase();
        if let Some(r) = rules.iter().find(|r| {
            r.is_chain
                && (r.category.to_ascii_lowercase().contains(&needle)
                    || r.raw_dork.to_ascii_lowercase().contains(&needle))
        }) {
            return Some(r);
        }
    }
    rules.iter().find(|r| r.is_chain).or_else(|| rules.first())
}

fn push_chain_finding(
    verified: &mut Vec<VerifiedMatch>,
    anchor: &CompiledDorkRule,
    severity: &str,
    cwe_id: &str,
    endpoint: String,
    ast_node_type: &str,
    snippet: String,
    confidence_bps: i64,
    entropy_bps: i64,
) {
    let duplicate = verified.iter().any(|existing| {
        existing.rule_id == anchor.rule_id
            && existing.matched_endpoint == endpoint
            && existing.ast_node_type == ast_node_type
    });
    if duplicate {
        return;
    }
    let (cvss_vector, cvss_score_bps) = map_cvss(severity, cwe_id);
    verified.push(VerifiedMatch {
        rule_id: anchor.rule_id,
        category: if anchor.category.starts_with("[CHAIN]") {
            anchor.category.clone()
        } else {
            format!("[CHAIN] {}", anchor.category)
        },
        is_chain: true,
        raw_dork: anchor.raw_dork.clone(),
        severity: severity.to_string(),
        cwe_id: cwe_id.to_string(),
        cvss_vector: cvss_vector.to_string(),
        cvss_score_bps,
        matched_endpoint: endpoint,
        ast_node_type: ast_node_type.to_string(),
        ast_context_snippet: snippet,
        shannon_entropy_bps: entropy_bps,
        confidence_bps,
        is_vendor_observation: false,
        is_shadow_downgraded: false,
    });
}

/// Cross-Asset & Cross-Finding [CHAIN] Correlator (P0 #1).
/// Upgrades isolated single-document evaluation to correlate signals spanning distinct
/// harvested assets on the same host (.git exposure, robots.txt disallow rules, Swagger/OpenAPI,
/// login portals, directory indexes, and high-entropy secrets).
fn correlate_chain_findings(
    rules: &[CompiledDorkRule],
    valid_docs: &[&HarvestedDoc],
    verified: &mut Vec<VerifiedMatch>,
    dedup: &mut HashSet<(i64, String)>,
) {
    if rules.is_empty() || valid_docs.len() < 2 {
        return;
    }

    let first_party_docs: Vec<&&HarvestedDoc> = valid_docs
        .iter()
        .filter(|d| !d.is_vendor_asset && d.status_code < 400)
        .collect();
    if first_party_docs.len() < 2 {
        return;
    }

    // 1. Multi-doc DorkExpr::And correlation for [CHAIN] rules that span multiple distinct URLs
    for rule in rules.iter().filter(|r| r.is_chain) {
        let mut branches = Vec::new();
        collect_and_branches(&rule.expr_tree, &mut branches);
        if branches.len() < 2 {
            continue;
        }
        let mut matched_urls: Vec<String> = Vec::new();
        let mut all_satisfied = true;
        for branch in &branches {
            let mut found_url: Option<String> = None;
            for doc in &first_party_docs {
                if eval_dork_expr(branch, doc) {
                    if rule_requires_dir_index(rule)
                        && !doc.has_dir_index_dom
                        && doc.doc_kind == DocKind::Html
                    {
                        continue;
                    }
                    if rule_is_login_portal(rule)
                        && !doc.has_login_dom
                        && doc.doc_kind == DocKind::Html
                    {
                        continue;
                    }
                    if !matched_urls.contains(&doc.url) {
                        found_url = Some(doc.url.clone());
                        break;
                    }
                    if found_url.is_none() {
                        found_url = Some(doc.url.clone());
                    }
                }
            }
            if let Some(u) = found_url {
                if !matched_urls.contains(&u) {
                    matched_urls.push(u);
                }
            } else {
                all_satisfied = false;
                break;
            }
        }
        if all_satisfied && matched_urls.len() >= 2 {
            let primary = matched_urls[0].clone();
            if dedup.insert((rule.rule_id, format!("CHAIN::{}", primary))) {
                let snippet = format!(
                    "Multi-asset [CHAIN] rule correlated across {} endpoints: {}",
                    matched_urls.len(),
                    matched_urls
                        .iter()
                        .take(4)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(" + ")
                );
                let sev = if rule.default_severity == "INFO" || rule.default_severity == "LOW" {
                    "MEDIUM"
                } else {
                    &rule.default_severity
                };
                push_chain_finding(
                    verified,
                    rule,
                    sev,
                    &rule.cwe_id,
                    primary,
                    "CHAIN_MULTI_ASSET_RULE",
                    snippet,
                    9300,
                    0,
                );
            }
        }
    }

    // 2. Semantic Attack-Chain Correlation (.git + robots.txt + Swagger/Login + Secrets)
    let git_doc = first_party_docs.iter().find(|d| d.is_git_exposed);
    let swagger_doc = first_party_docs.iter().find(|d| d.is_swagger_exposed);
    let login_doc = first_party_docs.iter().find(|d| d.has_login_dom);
    let dir_doc = first_party_docs.iter().find(|d| d.has_dir_index_dom);
    let robots_paths: Vec<String> = first_party_docs
        .iter()
        .flat_map(|d| d.robots_disallowed.iter().cloned())
        .collect();
    let high_secret_finding: Option<(String, i64)> = verified
        .iter()
        .find(|v| {
            !v.is_vendor_observation
                && !v.is_shadow_downgraded
                && (v.severity == "CRITICAL" || v.severity == "HIGH")
                && v.shannon_entropy_bps >= 320
        })
        .map(|v| (v.matched_endpoint.clone(), v.shannon_entropy_bps));

    if let Some(gdoc) = git_doc {
        let mut pivots = Vec::new();
        if !robots_paths.is_empty() {
            pivots.push(format!(
                "robots_disallow=[{}]",
                robots_paths
                    .iter()
                    .take(4)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if let Some(sdoc) = swagger_doc {
            pivots.push(format!("openapi={}", sdoc.path));
        }
        if let Some(ldoc) = login_doc {
            pivots.push(format!("login={}", ldoc.path));
        }
        if let Some(ddoc) = dir_doc {
            pivots.push(format!("dir_index={}", ddoc.path));
        }
        if let Some((ref sf_ep, _)) = high_secret_finding {
            pivots.push(format!("secret={}", sf_ep));
        }
        if !pivots.is_empty() {
            if let Some(anchor) = find_chain_anchor_rule(rules, &[".git", "juicy", "passwords"]) {
                let snippet = format!(
                    "Composite VCS recon chain: exposed_git={} correlated with {}",
                    gdoc.url,
                    pivots.join(" + ")
                );
                push_chain_finding(
                    verified,
                    anchor,
                    "CRITICAL",
                    "CWE-538",
                    gdoc.url.clone(),
                    "CHAIN_GIT_RECON_PIVOT",
                    snippet,
                    9700,
                    gdoc.body_entropy_bps,
                );
            }
        }
    }

    if !robots_paths.is_empty() {
        let accessible_disallowed = first_party_docs.iter().find(|d| {
            !d.path.eq_ignore_ascii_case("/robots.txt")
                && robots_paths.iter().any(|p| {
                    p.len() > 1
                        && d.path
                            .to_ascii_lowercase()
                            .starts_with(&p.to_ascii_lowercase())
                })
        });
        if accessible_disallowed.is_some()
            || swagger_doc.is_some()
            || (login_doc.is_some() && dir_doc.is_some())
        {
            if let Some(anchor) = find_chain_anchor_rule(rules, &["robots", "login", "juicy"]) {
                let primary_url = accessible_disallowed
                    .map(|d| d.url.clone())
                    .or_else(|| swagger_doc.map(|d| d.url.clone()))
                    .or_else(|| login_doc.map(|d| d.url.clone()))
                    .unwrap_or_else(|| first_party_docs[0].url.clone());
                let mut evidence = vec![format!(
                    "robots_disallow=[{}]",
                    robots_paths
                        .iter()
                        .take(5)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                )];
                if let Some(ad) = accessible_disallowed {
                    evidence.push(format!(
                        "live_disallowed_route={} (HTTP {})",
                        ad.path, ad.status_code
                    ));
                }
                if let Some(sd) = swagger_doc {
                    evidence.push(format!("openapi_schema={}", sd.path));
                }
                if let Some(ld) = login_doc {
                    evidence.push(format!("login_dom={}", ld.path));
                }
                if let Some(dd) = dir_doc {
                    evidence.push(format!("dir_index={}", ddoc_path(dd)));
                }
                let sev = if accessible_disallowed.is_some() || swagger_doc.is_some() {
                    "HIGH"
                } else {
                    "MEDIUM"
                };
                push_chain_finding(
                    verified,
                    anchor,
                    sev,
                    "CWE-200",
                    primary_url,
                    "CHAIN_ROBOTS_SURFACE_PIVOT",
                    format!("Cross-asset surface chain: {}", evidence.join(" + ")),
                    9200,
                    0,
                );
            }
        }
    }

    if let (Some(ddoc), Some((sf_ep, sf_entropy))) = (dir_doc.or(swagger_doc), high_secret_finding)
    {
        if ddoc.url != sf_ep {
            if let Some(anchor) = find_chain_anchor_rule(rules, &["passwords", "juicy"]) {
                let snippet = format!(
                    "Cross-asset credential chain: {} ({}) paired with verified secret at {}",
                    if ddoc.has_dir_index_dom {
                        "directory_index"
                    } else {
                        "openapi_surface"
                    },
                    ddoc.url,
                    sf_ep
                );
                push_chain_finding(
                    verified,
                    anchor,
                    "CRITICAL",
                    "CWE-538",
                    ddoc.url.clone(),
                    "CHAIN_SURFACE_SECRET_PIVOT",
                    snippet,
                    9600,
                    sf_entropy,
                );
            }
        }
    }
}

fn ddoc_path(doc: &HarvestedDoc) -> &str {
    &doc.path
}
