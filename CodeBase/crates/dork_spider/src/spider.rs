use crate::ast_verifier::{HarvestedDoc, build_harvested_doc, is_vendor_url};
use crate::dork_ast::CompiledDorkRule;
use crate::entropy::{dom_tag_simhash, format_simhash_hex, shannon_entropy_bps};
use rand::Rng;
use regex::Regex;
use scraper::{Html, Selector};
use serde::Deserialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use url::Url;

pub const MAX_HTML_PAGES: usize = 25;
pub const MAX_JS_FILES: usize = 50;
pub const MAX_CONFIG_FILES: usize = 50;
pub const MAX_ACTIVE_PROBES: usize = 45;
pub const PROBE_CONCURRENCY_LIMIT: usize = 2;
pub const PROBE_JITTER_MIN_MS: u64 = 250;
pub const PROBE_JITTER_MAX_MS: u64 = 750;
pub const WAF_COOLDOWN_MS: u64 = 1500; // Bounded cooldown before exiting active mode

pub const CHROME_UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

#[derive(Debug, Clone)]
pub struct SpiderConfig {
    pub target_url: String,
    pub max_depth: usize,
    pub stealth_mode: bool,
    pub allow_local_staging: bool,
    pub engagement_id: Option<String>,
    pub harvest_dir: Option<PathBuf>,
    pub keep_harvest: bool,
    pub jitter_min_ms: u64,
    pub jitter_max_ms: u64,
    pub proxy_url: Option<String>,
    pub custom_wordlist: Vec<String>,
    pub spa_seed_path: Option<PathBuf>,
}

impl Default for SpiderConfig {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            max_depth: 2,
            stealth_mode: true,
            allow_local_staging: false,
            engagement_id: None,
            harvest_dir: None,
            keep_harvest: false,
            jitter_min_ms: PROBE_JITTER_MIN_MS,
            jitter_max_ms: PROBE_JITTER_MAX_MS,
            proxy_url: None,
            custom_wordlist: Vec::new(),
            spa_seed_path: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct SpaSeedPayload {
    final_url: Option<String>,
    hydrated_html: Option<String>,
    #[serde(default)]
    xhr_urls: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SpiderResult {
    pub docs: Vec<HarvestedDoc>,
    pub baseline_latency_mean_ms: i64,
    pub baseline_404_simhash: u64,
    pub baseline_404_simhash_hex: String,
    pub baseline_404_entropy_bps: i64,
    pub detected_waf_vendor: String,
    pub waf_tripped: bool,
    pub html_pages_crawled: i64,
    pub js_files_crawled: i64,
    pub config_files_crawled: i64,
    pub vendor_observations: Vec<String>,
    pub technologies: Vec<String>,
    pub harvest_dir_used: PathBuf,
}

fn sanitize_header_val(raw: &str) -> String {
    raw.chars()
        .filter(|&c| c != '\r' && c != '\n' && c != '\0')
        .collect()
}

pub fn is_blocked_ip(ip: IpAddr, allow_local_staging: bool) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // Strictly block cloud metadata (169.254.169.254) even in local staging mode
            if octets == [169, 254, 169, 254] {
                return true;
            }
            if v4.is_link_local() || v4.is_unspecified() || v4.is_multicast() {
                return true;
            }
            if allow_local_staging {
                return false;
            }
            // RFC 6598 CGNAT 100.64.0.0/10
            let is_cgnat = octets[0] == 100 && (octets[1] & 0xC0) == 64;
            v4.is_loopback() || v4.is_private() || is_cgnat
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_blocked_ip(IpAddr::V4(mapped), allow_local_staging);
            }
            if v6.is_unspecified() || v6.is_multicast() || (v6.segments()[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            if allow_local_staging {
                return false;
            }
            v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Custom DNS pinning resolver wired directly into `ureq::AgentBuilder::resolver`
/// to eliminate TOCTOU DNS-rebinding windows between SSRF checks and TCP connect.
#[derive(Clone)]
pub struct PinnedSsrfResolver {
    allow_local_staging: bool,
    pinned: Arc<Mutex<HashMap<String, Vec<SocketAddr>>>>,
}

impl PinnedSsrfResolver {
    pub fn new(allow_local_staging: bool) -> Self {
        Self {
            allow_local_staging,
            pinned: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn resolve_and_pin(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
        let lower_host = host.trim_matches(&['[', ']'][..]).to_ascii_lowercase();
        if lower_host == "metadata.google.internal" || lower_host.ends_with(".internal") {
            return Err("Cloud metadata endpoint blocked by SSRF policy".to_string());
        }
        let cache_key = format!("{}:{}", lower_host, port);
        {
            let guard = self.pinned.lock().unwrap();
            if let Some(addrs) = guard.get(&cache_key) {
                return Ok(addrs.clone());
            }
        }

        if let Ok(ip) = lower_host.parse::<IpAddr>() {
            if is_blocked_ip(ip, self.allow_local_staging) {
                return Err(format!("Blocked IP address {} (SSRF policy)", ip));
            }
            let pinned_addrs = vec![SocketAddr::new(ip, port)];
            self.pinned
                .lock()
                .unwrap()
                .insert(cache_key, pinned_addrs.clone());
            return Ok(pinned_addrs);
        }

        let mut addrs: Vec<SocketAddr> = (lower_host.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| format!("DNS resolution failed for {}: {}", host, e))?
            .collect();

        if addrs.is_empty() {
            return Err(format!("No IP addresses resolved for {}", host));
        }

        for addr in &addrs {
            if is_blocked_ip(addr.ip(), self.allow_local_staging) {
                return Err(format!(
                    "Resolved IP {} for {} violates SSRF policy",
                    addr.ip(),
                    host
                ));
            }
        }

        // Prefer IPv4 first so hosts with unreachable IPv6 routes connect over IPv4 reliably.
        addrs.sort_by_key(|a| if a.is_ipv4() { 0u8 } else { 1u8 });
        self.pinned.lock().unwrap().insert(cache_key, addrs.clone());
        Ok(addrs)
    }

    pub fn pinned_ips_for(&self, host: &str, port: u16) -> Vec<IpAddr> {
        let lower_host = host.trim_matches(&['[', ']'][..]).to_ascii_lowercase();
        let cache_key = format!("{}:{}", lower_host, port);
        let guard = self.pinned.lock().unwrap();
        guard
            .get(&cache_key)
            .map(|list| list.iter().map(|s| s.ip()).collect())
            .unwrap_or_default()
    }
}

impl ureq::Resolver for PinnedSsrfResolver {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
        let (host, port) = if let Ok(sa) = netloc.parse::<SocketAddr>() {
            (sa.ip().to_string(), sa.port())
        } else if let Some((h, p_str)) = netloc.rsplit_once(':') {
            let p = p_str.parse::<u16>().map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
            })?;
            (h.to_string(), p)
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Missing port in netloc: {}", netloc),
            ));
        };

        self.resolve_and_pin(&host, port)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))
    }
}

pub fn verify_url_ssrf(raw_url: &str, allow_local_staging: bool) -> Result<Url, String> {
    let resolver = PinnedSsrfResolver::new(allow_local_staging);
    verify_url_ssrf_pinned(raw_url, allow_local_staging, &resolver, false)
}

pub fn verify_url_ssrf_pinned(
    raw_url: &str,
    allow_local_staging: bool,
    resolver: &PinnedSsrfResolver,
    allow_proxy_dns: bool,
) -> Result<Url, String> {
    let parsed = Url::parse(raw_url).map_err(|e| format!("Invalid URL: {}", e))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err("Only http and https schemes are permitted".to_string());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "Missing host in URL".to_string())?;
    let lower_host = host.trim_matches(&['[', ']'][..]).to_ascii_lowercase();
    if lower_host == "metadata.google.internal" || lower_host.ends_with(".internal") {
        return Err("Cloud metadata endpoint blocked by SSRF policy".to_string());
    }
    let port = parsed.port_or_known_default().unwrap_or(443);
    if let Ok(ip) = lower_host.parse::<IpAddr>() {
        if is_blocked_ip(ip, allow_local_staging) {
            return Err(format!("Blocked IP address {} (SSRF policy)", ip));
        }
        let _ = resolver.resolve_and_pin(host, port);
        return Ok(parsed);
    }

    match resolver.resolve_and_pin(host, port) {
        Ok(_) => Ok(parsed),
        Err(e) if allow_proxy_dns && e.starts_with("DNS resolution failed") => Ok(parsed),
        Err(e) => Err(e),
    }
}

pub fn is_allowed_domain(candidate: &Url, target_host: &str) -> bool {
    let Some(host) = candidate.host_str() else {
        return false;
    };
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let t = target_host.trim_end_matches('.').to_ascii_lowercase();
    if h == t || h.ends_with(&format!(".{}", t)) {
        return true;
    }
    // Allow canonical www.<apex> <-> <apex> redirection
    if let Some(apex) = t.strip_prefix("www.") {
        return h == apex || h.ends_with(&format!(".{}", apex));
    }
    false
}

pub fn validate_proxy_url(raw_proxy: &str, allow_local_staging: bool) -> Result<String, String> {
    let trimmed = raw_proxy.trim();
    let parsed = Url::parse(trimmed).map_err(|e| format!("Invalid proxy URL: {}", e))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("Outbound proxy must use http:// or https:// scheme".to_string());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "Proxy URL missing host".to_string())?
        .trim_matches(&['[', ']'][..])
        .to_ascii_lowercase();
    if host == "metadata.google.internal" || host.ends_with(".internal") {
        return Err("Proxy host cannot target internal cloud metadata".to_string());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_blocked_ip(ip, allow_local_staging) {
            return Err(format!("Proxy IP {} violates SSRF policy", ip));
        }
    }
    Ok(trimmed.to_string())
}

fn resolve_effective_proxy(
    explicit_proxy: &Option<String>,
    target_url: &Url,
    allow_local_staging: bool,
) -> Result<Option<String>, String> {
    if let Some(raw) = explicit_proxy {
        if !raw.trim().is_empty() {
            return validate_proxy_url(raw, allow_local_staging).map(Some);
        }
    }
    let target_host = target_url
        .host_str()
        .unwrap_or("")
        .trim_matches(&['[', ']'][..])
        .to_ascii_lowercase();
    if target_host == "127.0.0.1" || target_host == "localhost" || target_host == "::1" {
        return Ok(None);
    }
    let no_proxy = std::env::var("NO_PROXY")
        .or_else(|_| std::env::var("no_proxy"))
        .unwrap_or_default();
    if !no_proxy.is_empty() {
        for item in no_proxy.split(',').map(|s| s.trim().to_ascii_lowercase()) {
            if item == "*"
                || (!item.is_empty() && (target_host == item || target_host.ends_with(&item)))
            {
                return Ok(None);
            }
        }
    }

    let env_proxy = if target_url.scheme() == "https" {
        std::env::var("HTTPS_PROXY")
            .or_else(|_| std::env::var("https_proxy"))
            .or_else(|_| std::env::var("HTTP_PROXY"))
            .or_else(|_| std::env::var("http_proxy"))
            .ok()
    } else {
        std::env::var("HTTP_PROXY")
            .or_else(|_| std::env::var("http_proxy"))
            .ok()
    };

    if let Some(p) = env_proxy {
        if !p.trim().is_empty() {
            return validate_proxy_url(&p, allow_local_staging).map(Some);
        }
    }
    Ok(None)
}

fn build_http_agent(
    resolver: PinnedSsrfResolver,
    proxy_url: Option<&str>,
) -> Result<ureq::Agent, String> {
    let mut builder = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(6))
        .timeout_read(Duration::from_secs(12))
        .redirects(0) // Handle redirects explicitly so every hop enforces SSRF + domain boundary
        .resolver(resolver);

    if let Some(raw_proxy) = proxy_url {
        let proxy = ureq::Proxy::new(raw_proxy)
            .map_err(|e| format!("Failed configuring outbound proxy {}: {}", raw_proxy, e))?;
        builder = builder.proxy(proxy);
    }

    Ok(builder.build())
}

fn apply_stealth_headers(mut req: ureq::Request, engagement_id: &Option<String>) -> ureq::Request {
    req = req
        .set("User-Agent", CHROME_UA)
        .set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,application/json,text/javascript,*/*;q=0.8")
        .set("Accept-Language", "en-US,en;q=0.9")
        .set("Sec-Ch-Ua", r#""Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99""#)
        .set("Sec-Ch-Ua-Mobile", "?0")
        .set("Sec-Ch-Ua-Platform", r#""Linux""#)
        .set("Sec-Fetch-Dest", "document")
        .set("Sec-Fetch-Mode", "navigate")
        .set("Sec-Fetch-Site", "none")
        .set("Upgrade-Insecure-Requests", "1");

    if let Some(raw_eng) = engagement_id {
        let eng = sanitize_header_val(raw_eng.trim());
        if !eng.is_empty() {
            req = req
                .set("X-Security-Engagement", &eng)
                .set("X-Authorized-Audit", "true")
                .set("Pragma", "akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, akamai-x-get-cache-key, akamai-x-get-true-cache-key, no-cache")
                .set("Cache-Control", "no-cache, no-store, max-age=0");

            let lower_eng = eng.to_ascii_lowercase();
            if lower_eng.starts_with("staging:") || lower_eng.starts_with("akamai:") {
                if let Some((_, token)) = eng.split_once(':') {
                    req = req
                        .set("X-Akamai-Staging", "true")
                        .set("X-Akamai-Edge-Token", token.trim());
                }
            }
        }
    }
    req
}

struct FetchedResponse {
    final_url: String,
    status: u16,
    content_type: String,
    headers_joined: String,
    body: String,
    waf_vendor: Option<String>,
    waf_blocked: bool,
    latency_ms: i64,
}

fn detect_waf(status: u16, headers_joined: &str, body: &str) -> (Option<String>, bool) {
    let hl = headers_joined.to_ascii_lowercase();
    let bl = body.to_ascii_lowercase();

    let vendor = if hl.contains("cf-ray")
        || hl.contains("cf-mitigated")
        || hl.contains("server: cloudflare")
    {
        Some("CLOUDFLARE".to_string())
    } else if hl.contains("akamaighost") || hl.contains("akamai") {
        Some("AKAMAI".to_string())
    } else if hl.contains("x-amzn-waf-action") || hl.contains("awselb") {
        Some("AWS_WAF".to_string())
    } else if hl.contains("x-iinfo") || hl.contains("incap_ses") {
        Some("IMPERVA".to_string())
    } else {
        None
    };

    let blocked = status == 429
        || status == 503
        || (status == 403
            && (vendor.is_some()
                || bl.contains("attention required! | cloudflare")
                || bl.contains("access denied") && bl.contains("reference #")));

    (vendor, blocked)
}

fn fetch_url_safe(
    agent: &ureq::Agent,
    url_str: &str,
    target_host: &str,
    allow_local_staging: bool,
    engagement_id: &Option<String>,
    resolver: &PinnedSsrfResolver,
    allow_proxy_dns: bool,
) -> Result<FetchedResponse, String> {
    let mut current = url_str.to_string();
    for _hop in 0..5 {
        let parsed =
            verify_url_ssrf_pinned(&current, allow_local_staging, resolver, allow_proxy_dns)?;
        if !is_allowed_domain(&parsed, target_host) {
            return Err(format!(
                "Redirect escaped target domain boundary: {}",
                current
            ));
        }
        let start = Instant::now();
        let req = apply_stealth_headers(agent.get(&current), engagement_id);
        let resp = match req.call() {
            Ok(r) => r,
            Err(ureq::Error::Status(_code, r)) => r,
            Err(e) => return Err(format!("HTTP error for {}: {}", current, e)),
        };
        let latency_ms = start.elapsed().as_millis() as i64;
        let status = resp.status();

        if (300..400).contains(&status) {
            if let Some(loc) = resp.header("location") {
                if let Ok(next_url) = parsed.join(loc) {
                    current = next_url.to_string();
                    continue;
                }
            }
        }

        let content_type = resp
            .header("content-type")
            .unwrap_or("text/plain")
            .to_string();
        let mut hdr_lines = Vec::new();
        for name in resp.headers_names() {
            if let Some(val) = resp.header(&name) {
                hdr_lines.push(format!("{}: {}", name.to_ascii_lowercase(), val));
            }
        }
        let headers_joined = hdr_lines.join("\n");

        let mut reader = resp.into_reader();
        let mut buf = Vec::new();
        use std::io::Read;
        let _ = std::io::Read::by_ref(&mut reader)
            .take(768 * 1024)
            .read_to_end(&mut buf);
        let body = String::from_utf8_lossy(&buf).to_string();
        let (waf_vendor, waf_blocked) = detect_waf(status, &headers_joined, &body);

        return Ok(FetchedResponse {
            final_url: current,
            status,
            content_type,
            headers_joined,
            body,
            waf_vendor,
            waf_blocked,
            latency_ms,
        });
    }
    Err(format!("Too many redirects for {}", url_str))
}

/// Extracts Webpack / Vite / Rollup chunk paths using linear-time Thompson NFA regexes.
pub fn extract_bundler_chunks(js_content: &str, base_url: &Url) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    let chunk_map_re = Regex::new(r#"(\d+)\s*:\s*"([0-9a-fA-F]{6,20})""#).unwrap();
    let string_path_re = Regex::new(
        r#"["']((?:\./|/)?(?:assets|chunks|js|static|dist)?/?[A-Za-z0-9_.\-/~]+\.(?:chunk\.js|js|mjs|json|yaml|yml|env|conf))["']"#,
    )
    .unwrap();
    let vite_import_re = Regex::new(r#"import\(\s*["'](\./[^"']+\.(?:js|mjs))["']\s*\)"#).unwrap();

    if js_content.contains("__webpack_require__") || js_content.contains("jsonpScriptSrc") {
        for cap in chunk_map_re.captures_iter(js_content) {
            if let (Some(id), Some(hash)) = (cap.get(1), cap.get(2)) {
                let candidate = format!("{}.{}.chunk.js", id.as_str(), hash.as_str());
                if let Ok(resolved) = base_url.join(&candidate) {
                    let s = resolved.to_string();
                    if seen.insert(s.clone()) {
                        out.push(s);
                    }
                }
            }
        }
    }

    for cap in vite_import_re.captures_iter(js_content) {
        if let Some(rel) = cap.get(1) {
            if let Ok(resolved) = base_url.join(rel.as_str()) {
                let s = resolved.to_string();
                if seen.insert(s.clone()) {
                    out.push(s);
                }
            }
        }
    }

    for cap in string_path_re.captures_iter(js_content) {
        if let Some(rel) = cap.get(1) {
            let p = rel.as_str();
            if p.contains("node_modules") || p.starts_with("//") {
                continue;
            }
            if let Ok(resolved) = base_url.join(p) {
                let s = resolved.to_string();
                if seen.insert(s.clone()) {
                    out.push(s);
                }
            }
        }
    }

    out
}

fn provision_harvest_dir(custom_dir: Option<&Path>) -> Result<PathBuf, String> {
    let dir = match custom_dir {
        Some(p) => p.to_path_buf(),
        None => {
            let suffix: u64 = rand::thread_rng().r#gen();
            std::env::temp_dir().join(format!("blackroute_dork_{:016x}", suffix))
        }
    };
    if let Ok(meta) = fs::symlink_metadata(&dir) {
        if meta.file_type().is_symlink() {
            return Err(format!(
                "CWE-377 violation: harvest path {:?} is a symlink",
                dir
            ));
        }
    }
    fs::create_dir_all(&dir).map_err(|e| format!("Failed creating harvest dir: {}", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
    Ok(dir)
}

fn write_sandboxed_harvest(dir: &Path, filename: &str, body: &str) {
    let safe_name: String = filename
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let target = dir.join(safe_name);
    if let Ok(meta) = fs::symlink_metadata(&target) {
        if meta.file_type().is_symlink() {
            return;
        }
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        opts.custom_flags(libc_o_nofollow()).mode(0o600);
    }
    if let Ok(mut f) = opts.open(&target) {
        let _ = f.write_all(body.as_bytes());
    }
}

#[cfg(target_os = "linux")]
fn libc_o_nofollow() -> i32 {
    0o400000
}

#[cfg(not(target_os = "linux"))]
fn libc_o_nofollow() -> i32 {
    0
}

fn detect_technologies(
    docs: &[HarvestedDoc],
    headers_samples: &[String],
) -> (Vec<String>, Vec<String>) {
    let mut techs = HashSet::new();
    let mut vendors = HashSet::new();
    let joined_hdrs = headers_samples.join("\n").to_ascii_lowercase();

    if joined_hdrs.contains("_abck")
        || joined_hdrs.contains("bm_sz")
        || joined_hdrs.contains("akamai")
    {
        vendors.insert("Akamai Bot Manager / Edge".to_string());
    }
    if joined_hdrs.contains("cloudflare") || joined_hdrs.contains("cf-ray") {
        vendors.insert("Cloudflare WAF".to_string());
    }
    if joined_hdrs.contains("apache") {
        techs.insert("Apache HTTP Server".to_string());
    }
    if joined_hdrs.contains("nginx") {
        techs.insert("Nginx".to_string());
    }
    if joined_hdrs.contains("x-powered-by: php") {
        techs.insert("PHP".to_string());
    }

    for doc in docs {
        let lower = doc.raw_body.to_ascii_lowercase();
        if is_vendor_url(&doc.url) || lower.contains("tiqcdn") || lower.contains("utag.js") {
            vendors.insert("Tealium iQ Tag Management".to_string());
        }
        if lower.contains("adobe") && (lower.contains("mbox") || lower.contains("amcv")) {
            vendors.insert("Adobe Experience Cloud".to_string());
        }
        if lower.contains("google-analytics.com") || lower.contains("googletagmanager.com") {
            vendors.insert("Google Analytics / GTM".to_string());
        }
        if lower.contains("__next_data__") || lower.contains("/_next/") {
            techs.insert("Next.js".to_string());
        }
        if lower.contains("__webpack_require__") {
            techs.insert("Webpack".to_string());
        }
        if lower.contains("__vitepreload") || lower.contains("vite") {
            techs.insert("Vite".to_string());
        }
        if lower.contains("wp-content") || lower.contains("wp-includes") {
            techs.insert("WordPress".to_string());
        }
    }

    (techs.into_iter().collect(), vendors.into_iter().collect())
}

fn is_skippable_static_asset(url: &Url) -> bool {
    let p = url.path().to_ascii_lowercase();
    [
        ".css", ".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif", ".woff",
        ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm", ".mp3", ".wav", ".ogg", ".pdf",
    ]
    .iter()
    .any(|ext| p.ends_with(ext))
}

pub fn run_spider(
    config: &SpiderConfig,
    rules: &[CompiledDorkRule],
) -> Result<SpiderResult, String> {
    let initial_url = Url::parse(&config.target_url)
        .map_err(|e| format!("Invalid target URL {}: {}", config.target_url, e))?;
    let effective_proxy =
        resolve_effective_proxy(&config.proxy_url, &initial_url, config.allow_local_staging)?;
    let allow_proxy_dns = effective_proxy.is_some();

    let resolver = PinnedSsrfResolver::new(config.allow_local_staging);
    let mut root_parsed = verify_url_ssrf_pinned(
        &config.target_url,
        config.allow_local_staging,
        &resolver,
        allow_proxy_dns,
    )?;
    let mut target_host = root_parsed
        .host_str()
        .ok_or_else(|| "Missing target host".to_string())?
        .to_ascii_lowercase();
    let port = root_parsed.port_or_known_default().unwrap_or(443);
    let pinned_ips = resolver.pinned_ips_for(&target_host, port);
    let ip_summary = if pinned_ips.is_empty() {
        "proxy-resolved".to_string()
    } else {
        pinned_ips
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(",")
    };
    let egress_mode = if let Some(ref p) = effective_proxy {
        format!("OUTBOUND PROXY {}", p)
    } else if config.allow_local_staging {
        "LOCAL STAGING EGRESS".to_string()
    } else {
        "OUTBOUND INTERNET EGRESS".to_string()
    };
    eprintln!(
        "[NET] Target {} pinned to [{}] ({} // GUI LOOPBACK 127.0.0.1)",
        config.target_url, ip_summary, egress_mode
    );

    let harvest_dir = provision_harvest_dir(config.harvest_dir.as_deref())?;
    let agent = build_http_agent(resolver.clone(), effective_proxy.as_deref())?;

    eprintln!(
        "[SPIDER] Phase 1: Baseline & WAF Profiling for {}",
        config.target_url
    );

    // Phase 1: Baseline & WAF Profiling (Root + 2 random nonexistent 404 probes)
    let mut latencies = Vec::new();
    let mut detected_waf = "NONE".to_string();
    let mut header_samples = Vec::new();
    let mut docs: Vec<HarvestedDoc> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();

    match fetch_url_safe(
        &agent,
        &config.target_url,
        &target_host,
        config.allow_local_staging,
        &config.engagement_id,
        &resolver,
        allow_proxy_dns,
    ) {
        Ok(root_resp) => {
            latencies.push(root_resp.latency_ms);
            header_samples.push(root_resp.headers_joined.clone());
            if let Some(w) = root_resp.waf_vendor {
                detected_waf = w;
            }
            if let Ok(final_parsed) = Url::parse(&root_resp.final_url) {
                if let Some(fh) = final_parsed.host_str() {
                    let fh_low = fh.to_ascii_lowercase();
                    if fh_low != target_host {
                        target_host = fh_low;
                    }
                }
                root_parsed = final_parsed;
            }
            visited.insert(root_resp.final_url.clone());
            visited.insert(config.target_url.clone());
            write_sandboxed_harvest(&harvest_dir, "0000_root.html", &root_resp.body);
            docs.push(build_harvested_doc(
                &root_resp.final_url,
                root_resp.status,
                &root_resp.content_type,
                &root_resp.body,
            ));
        }
        Err(e) => {
            return Err(format!(
                "Unable to connect to target {}: {}",
                config.target_url, e
            ));
        }
    }

    let mut baseline_404_simhash: u64 = 0;
    let mut baseline_404_entropy_bps: i64 = 0;
    for idx in 0..2 {
        let rand_hex: u32 = rand::thread_rng().r#gen();
        if let Ok(probe_404) =
            root_parsed.join(&format!("/_adk_404_probe_{}_{:08x}", idx, rand_hex))
        {
            if let Ok(r404) = fetch_url_safe(
                &agent,
                probe_404.as_str(),
                &target_host,
                config.allow_local_staging,
                &config.engagement_id,
                &resolver,
                allow_proxy_dns,
            ) {
                latencies.push(r404.latency_ms);
                if baseline_404_simhash == 0 {
                    baseline_404_simhash = dom_tag_simhash(&r404.body);
                    baseline_404_entropy_bps = shannon_entropy_bps(&r404.body);
                }
            }
        }
    }

    // Optional passive /robots.txt discovery (ignores 404 or HTML catch-alls cleanly)
    let mut robots_disallowed_paths: Vec<String> = Vec::new();
    if let Ok(robots_url) = root_parsed.join("/robots.txt") {
        let robots_str = robots_url.to_string();
        if visited.insert(robots_str.clone()) {
            if let Ok(r_resp) = fetch_url_safe(
                &agent,
                &robots_str,
                &target_host,
                config.allow_local_staging,
                &config.engagement_id,
                &resolver,
                allow_proxy_dns,
            ) {
                let ct_low = r_resp.content_type.to_ascii_lowercase();
                let body_trim = r_resp.body.trim_start().to_ascii_lowercase();
                if r_resp.status == 200
                    && !ct_low.contains("text/html")
                    && !body_trim.starts_with("<!doctype")
                    && !body_trim.starts_with("<html")
                {
                    write_sandboxed_harvest(&harvest_dir, "0000_robots.txt", &r_resp.body);
                    let r_doc = build_harvested_doc(
                        &r_resp.final_url,
                        r_resp.status,
                        &r_resp.content_type,
                        &r_resp.body,
                    );
                    robots_disallowed_paths = r_doc.robots_disallowed.clone();
                    docs.push(r_doc);
                }
            }
        }
    }

    let baseline_latency_mean_ms = if latencies.is_empty() {
        0
    } else {
        latencies.iter().sum::<i64>() / latencies.len() as i64
    };
    let simhash_hex = format_simhash_hex(baseline_404_simhash);
    eprintln!(
        "[SPIDER] Baseline latency={}ms | 404 SimHash={} | WAF={}",
        baseline_latency_mean_ms, simhash_hex, detected_waf
    );

    // Phase 2: Bounded BFS Asset Spidering (Depth <= config.max_depth, capped 25 HTML / 50 JS / 50 Config)
    let max_depth = config.max_depth.clamp(1, 3);
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    let mut html_count = 1usize;
    let mut js_count = 0usize;
    let mut config_count = 0usize;

    // Seed queue from root HTML links & scripts
    let enqueue_from_doc = |doc: &HarvestedDoc,
                            depth: usize,
                            visited: &mut HashSet<String>,
                            queue: &mut VecDeque<(String, usize)>| {
        if depth >= max_depth {
            return;
        }
        let Ok(base) = Url::parse(&doc.url) else {
            return;
        };
        let document = Html::parse_document(&doc.raw_body);
        let link_sel = Selector::parse("a[href], script[src], link[href], form[action]").unwrap();
        for el in document.select(&link_sel) {
            let raw_attr = el
                .value()
                .attr("href")
                .or_else(|| el.value().attr("src"))
                .or_else(|| el.value().attr("action"));
            if let Some(raw_link) = raw_attr {
                let trimmed = raw_link.trim();
                if trimmed.is_empty()
                    || trimmed.starts_with('#')
                    || trimmed.starts_with("javascript:")
                    || trimmed.starts_with("mailto:")
                    || trimmed.starts_with("data:")
                {
                    continue;
                }
                if let Ok(mut abs) = base.join(trimmed) {
                    abs.set_fragment(None);
                    if is_skippable_static_asset(&abs) {
                        continue;
                    }
                    if is_allowed_domain(&abs, &target_host) {
                        let s = abs.to_string();
                        if visited.insert(s.clone()) {
                            queue.push_back((s, depth + 1));
                        }
                    }
                }
            }
        }
        // Also extract JS bundler chunks if JS doc
        if doc.doc_kind == crate::ast_verifier::DocKind::JavaScript {
            for chunk_url in extract_bundler_chunks(&doc.raw_body, &base) {
                if let Ok(abs) = Url::parse(&chunk_url) {
                    if !is_skippable_static_asset(&abs)
                        && is_allowed_domain(&abs, &target_host)
                        && visited.insert(chunk_url.clone())
                    {
                        queue.push_back((chunk_url, depth + 1));
                    }
                }
            }
        }
    };

    if let Some(root_doc) = docs.first() {
        enqueue_from_doc(root_doc, 0, &mut visited, &mut queue);
    }

    // Optional Stage-0 SPA Hydration Seed Ingestion (P0 #2)
    if let Some(ref seed_path) = config.spa_seed_path {
        if let Ok(seed_raw) = fs::read_to_string(seed_path) {
            if let Ok(seed) = serde_json::from_str::<SpaSeedPayload>(&seed_raw) {
                let seed_url = seed
                    .final_url
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .unwrap_or(&config.target_url);
                if let Some(ref html_body) = seed.hydrated_html {
                    if !html_body.trim().is_empty() {
                        write_sandboxed_harvest(&harvest_dir, "0000_spa_hydrated.html", html_body);
                        let spa_doc = build_harvested_doc(
                            seed_url,
                            200,
                            "text/html; charset=utf-8",
                            html_body,
                        );
                        enqueue_from_doc(&spa_doc, 0, &mut visited, &mut queue);
                        docs.push(spa_doc);
                        html_count += 1;
                    }
                }
                for xhr in seed.xhr_urls {
                    if let Ok(mut abs) = root_parsed.join(xhr.trim()) {
                        abs.set_fragment(None);
                        if !is_skippable_static_asset(&abs) && is_allowed_domain(&abs, &target_host)
                        {
                            let s = abs.to_string();
                            if visited.insert(s.clone()) {
                                queue.push_back((s, 1));
                            }
                        }
                    }
                }
                eprintln!("[SPIDER] Ingested Stage-0 SPA hydrated DOM & XHR seed routes");
            }
        }
    }

    let crawl_start = Instant::now();
    let mut file_idx = 1usize;
    while let Some((next_url, depth)) = queue.pop_front() {
        if crawl_start.elapsed() > Duration::from_secs(35) {
            eprintln!(
                "[SPIDER] Per-target BFS time budget reached; transitioning to AST verification."
            );
            break;
        }
        let path_only = Url::parse(&next_url)
            .map(|u| u.path().to_ascii_lowercase())
            .unwrap_or_else(|_| {
                next_url
                    .split('?')
                    .next()
                    .unwrap_or(&next_url)
                    .to_ascii_lowercase()
            });
        let looks_js = path_only.ends_with(".js") || path_only.ends_with(".mjs");
        let looks_cfg = [
            ".json", ".yaml", ".yml", ".xml", ".conf", ".env", ".log", ".txt", ".sql",
        ]
        .iter()
        .any(|ext| path_only.ends_with(ext));

        if looks_js && js_count >= MAX_JS_FILES {
            continue;
        }
        if looks_cfg && config_count >= MAX_CONFIG_FILES {
            continue;
        }
        if !looks_js && !looks_cfg && html_count >= MAX_HTML_PAGES {
            continue;
        }

        if let Ok(resp) = fetch_url_safe(
            &agent,
            &next_url,
            &target_host,
            config.allow_local_staging,
            &config.engagement_id,
            &resolver,
            allow_proxy_dns,
        ) {
            header_samples.push(resp.headers_joined.clone());
            let doc =
                build_harvested_doc(&resp.final_url, resp.status, &resp.content_type, &resp.body);
            match doc.doc_kind {
                crate::ast_verifier::DocKind::JavaScript => js_count += 1,
                crate::ast_verifier::DocKind::Html => html_count += 1,
                _ => config_count += 1,
            }
            let ext_tag = match doc.doc_kind {
                crate::ast_verifier::DocKind::JavaScript => "js",
                crate::ast_verifier::DocKind::Json => "json",
                crate::ast_verifier::DocKind::Yaml => "yaml",
                crate::ast_verifier::DocKind::Sql => "sql",
                crate::ast_verifier::DocKind::Config => "conf",
                crate::ast_verifier::DocKind::Log => "log",
                crate::ast_verifier::DocKind::Html => "html",
                crate::ast_verifier::DocKind::Text => "txt",
            };
            write_sandboxed_harvest(
                &harvest_dir,
                &format!("{:04}_asset.{}", file_idx, ext_tag),
                &resp.body,
            );
            file_idx += 1;
            enqueue_from_doc(&doc, depth, &mut visited, &mut queue);
            docs.push(doc);
        }
    }
    eprintln!(
        "[SPIDER] BFS Crawl complete: {} HTML, {} JS, {} Config/Text assets harvested",
        html_count, js_count, config_count
    );

    // Phase 3: Paced Active Dork Probing (when !stealth_mode OR custom wordlist supplied)
    let mut waf_tripped = false;
    if !config.stealth_mode || !config.custom_wordlist.is_empty() {
        let mut candidate_paths: Vec<String> = Vec::new();
        let mut seen_paths: HashSet<String> = HashSet::new();

        for custom in &config.custom_wordlist {
            let trimmed = custom.trim();
            if !trimmed.is_empty() && !trimmed.contains("..") && !trimmed.contains('\\') {
                let norm = if trimmed.starts_with('/') {
                    trimmed.to_string()
                } else {
                    format!("/{}", trimmed)
                };
                if seen_paths.insert(norm.clone()) {
                    candidate_paths.push(norm);
                }
            }
        }

        if !config.stealth_mode {
            for rpath in &robots_disallowed_paths {
                let clean = rpath.trim().trim_end_matches('*');
                if clean.starts_with('/')
                    && clean.len() > 1
                    && !clean.contains(' ')
                    && seen_paths.insert(clean.to_string())
                {
                    candidate_paths.push(clean.to_string());
                }
            }
            // Prioritize [CHAIN] rules first, then standard rules
            for chain_pass in [true, false] {
                for rule in rules.iter().filter(|r| r.is_chain == chain_pass) {
                    for p in &rule.candidate_probe_paths {
                        if seen_paths.insert(p.clone()) {
                            candidate_paths.push(p.clone());
                        }
                    }
                }
            }
        }
        candidate_paths.truncate(MAX_ACTIVE_PROBES);
        let j_min = config.jitter_min_ms.min(5000);
        let j_max = config.jitter_max_ms.clamp(j_min, 5000);

        eprintln!(
            "[SPIDER] Phase 3: Active Verification enabled ({} jitter-paced probes [{}-{}ms], concurrency={})",
            candidate_paths.len(),
            j_min,
            j_max,
            PROBE_CONCURRENCY_LIMIT
        );

        let tripped = Arc::new(AtomicBool::new(false));
        let path_queue = Arc::new(std::sync::Mutex::new(VecDeque::from(candidate_paths)));
        let collected = Arc::new(std::sync::Mutex::new(Vec::<HarvestedDoc>::new()));
        let waf_label = Arc::new(std::sync::Mutex::new(detected_waf.clone()));
        let visited_shared = Arc::new(std::sync::Mutex::new(visited.clone()));

        let mut handles = Vec::new();
        for _ in 0..PROBE_CONCURRENCY_LIMIT {
            let q = Arc::clone(&path_queue);
            let col = Arc::clone(&collected);
            let trip = Arc::clone(&tripped);
            let waf_l = Arc::clone(&waf_label);
            let vis = Arc::clone(&visited_shared);
            let root_u = root_parsed.clone();
            let thost = target_host.clone();
            let eng = config.engagement_id.clone();
            let allow_local = config.allow_local_staging;
            let worker_resolver = resolver.clone();
            let worker_proxy = effective_proxy.clone();

            handles.push(thread::spawn(move || {
                let Ok(worker_agent) =
                    build_http_agent(worker_resolver.clone(), worker_proxy.as_deref())
                else {
                    return;
                };
                loop {
                    if trip.load(Ordering::Acquire) {
                        break;
                    }
                    let next_path = {
                        let mut guard = q.lock().unwrap();
                        guard.pop_front()
                    };
                    let Some(rel_path) = next_path else {
                        break;
                    };

                    // Randomized pre-request jitter
                    if j_max > 0 {
                        let jitter_ms: u64 = if j_min == j_max {
                            j_min
                        } else {
                            rand::thread_rng().gen_range(j_min..=j_max)
                        };
                        if jitter_ms > 0 {
                            thread::sleep(Duration::from_millis(jitter_ms));
                        }
                    }

                    if trip.load(Ordering::Acquire) {
                        break;
                    }
                    let Ok(full_u) = root_u.join(&rel_path) else {
                        continue;
                    };
                    let full_str = full_u.to_string();
                    {
                        let mut vguard = vis.lock().unwrap();
                        if !vguard.insert(full_str.clone()) {
                            continue;
                        }
                    }

                    if let Ok(resp) = fetch_url_safe(
                        &worker_agent,
                        &full_str,
                        &thost,
                        allow_local,
                        &eng,
                        &worker_resolver,
                        allow_proxy_dns,
                    ) {
                        if resp.waf_blocked {
                            trip.store(true, Ordering::Release);
                            let vendor_str = resp.waf_vendor.unwrap_or_else(|| "WAF_RATE_LIMIT".to_string());
                            {
                                let mut wguard = waf_l.lock().unwrap();
                                *wguard = vendor_str.clone();
                            }
                            eprintln!(
                                "[WARN: WAF_CIRCUIT_BREAKER_TRIPPED] Vendor={} Status={} Path={} — halting active probes",
                                vendor_str, resp.status, rel_path
                            );
                            thread::sleep(Duration::from_millis(WAF_COOLDOWN_MS));
                            break;
                        }
                        if resp.status == 200 {
                            let doc = build_harvested_doc(
                                &resp.final_url,
                                resp.status,
                                &resp.content_type,
                                &resp.body,
                            );
                            let mut cguard = col.lock().unwrap();
                            cguard.push(doc);
                        }
                    }
                }
            }));
        }

        for h in handles {
            let _ = h.join();
        }

        waf_tripped = tripped.load(Ordering::Acquire);
        detected_waf = waf_label.lock().unwrap().clone();
        let active_docs = collected.lock().unwrap().clone();
        for doc in active_docs {
            let ext_tag = match doc.doc_kind {
                crate::ast_verifier::DocKind::JavaScript => {
                    js_count += 1;
                    "js"
                }
                crate::ast_verifier::DocKind::Json => {
                    config_count += 1;
                    "json"
                }
                crate::ast_verifier::DocKind::Yaml => {
                    config_count += 1;
                    "yaml"
                }
                crate::ast_verifier::DocKind::Sql => {
                    config_count += 1;
                    "sql"
                }
                crate::ast_verifier::DocKind::Config => {
                    config_count += 1;
                    "conf"
                }
                crate::ast_verifier::DocKind::Log => {
                    config_count += 1;
                    "log"
                }
                crate::ast_verifier::DocKind::Html => {
                    html_count += 1;
                    "html"
                }
                crate::ast_verifier::DocKind::Text => {
                    config_count += 1;
                    "txt"
                }
            };
            write_sandboxed_harvest(
                &harvest_dir,
                &format!("{:04}_active.{}", file_idx, ext_tag),
                &doc.raw_body,
            );
            file_idx += 1;
            docs.push(doc);
        }
    }

    let (technologies, vendor_observations) = detect_technologies(&docs, &header_samples);

    if !config.keep_harvest {
        let _ = fs::remove_dir_all(&harvest_dir);
    }

    Ok(SpiderResult {
        docs,
        baseline_latency_mean_ms,
        baseline_404_simhash,
        baseline_404_simhash_hex: simhash_hex,
        baseline_404_entropy_bps,
        detected_waf_vendor: detected_waf,
        waf_tripped,
        html_pages_crawled: html_count as i64,
        js_files_crawled: js_count as i64,
        config_files_crawled: config_count as i64,
        vendor_observations,
        technologies,
        harvest_dir_used: harvest_dir,
    })
}
