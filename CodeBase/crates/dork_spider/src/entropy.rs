use regex::Regex;
use scraper::{Html, Selector};
use std::collections::HashMap;

/// Computes Shannon Entropy H(X) in bits/character.
pub fn shannon_entropy(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq: HashMap<u8, usize> = HashMap::new();
    let bytes = data.as_bytes();
    for &b in bytes {
        *freq.entry(b).or_insert(0) += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0_f64;
    for &count in freq.values() {
        let p = count as f64 / len;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Converts Shannon Entropy to integer basis points (e.g., 3.42 bits/char -> 342)
/// to avoid floating-point drift in SQLite persistence (Section 5 / Pillar I).
pub fn shannon_entropy_bps(data: &str) -> i64 {
    (shannon_entropy(data) * 100.0).round() as i64
}

/// Computes a 64-bit structural DOM Tag SimHash for Soft-404 differential comparison.
pub fn dom_tag_simhash(html: &str) -> u64 {
    let document = Html::parse_document(html);
    let mut weights = [0i64; 64];

    let all_sel = Selector::parse("*").unwrap();
    let mut tags: Vec<String> = Vec::new();
    for el in document.select(&all_sel).take(256) {
        let name = el.value().name().to_ascii_lowercase();
        let class_attr = el.value().attr("class").unwrap_or("");
        if class_attr.is_empty() {
            tags.push(name);
        } else {
            tags.push(format!(
                "{}:{}",
                name,
                class_attr.split_whitespace().next().unwrap_or("")
            ));
        }
    }

    if tags.is_empty() {
        // Fallback for non-HTML payloads (plain text / JSON / YAML)
        for chunk in html.as_bytes().chunks(16).take(64) {
            let h = fnv1a_64(chunk);
            for bit in 0..64 {
                if (h >> bit) & 1 == 1 {
                    weights[bit] += 1;
                } else {
                    weights[bit] -= 1;
                }
            }
        }
    } else {
        // Bigram shingles of structural DOM tags preserve layout order
        for window in tags.windows(2) {
            let feature = format!("{}->{}", window[0], window[1]);
            let h = fnv1a_64(feature.as_bytes());
            for bit in 0..64 {
                if (h >> bit) & 1 == 1 {
                    weights[bit] += 1;
                } else {
                    weights[bit] -= 1;
                }
            }
        }
        if tags.len() == 1 {
            let h = fnv1a_64(tags[0].as_bytes());
            for bit in 0..64 {
                if (h >> bit) & 1 == 1 {
                    weights[bit] += 1;
                } else {
                    weights[bit] -= 1;
                }
            }
        }
    }

    let mut hash = 0u64;
    for (bit, &w) in weights.iter().enumerate() {
        if w > 0 {
            hash |= 1u64 << bit;
        }
    }
    hash
}

pub fn format_simhash_hex(hash: u64) -> String {
    format!("{:016x}", hash)
}

pub fn parse_simhash_hex(hex_str: &str) -> Option<u64> {
    u64::from_str_radix(hex_str.trim(), 16).ok()
}

/// Returns similarity in basis points (0..=10000, where 9200 = 0.92).
pub fn simhash_similarity_bps(a: u64, b: u64) -> i64 {
    let diff = (a ^ b).count_ones() as i64;
    ((64 - diff) * 10_000) / 64
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[derive(Debug, Clone)]
pub struct SecretEval {
    pub matched_key: String,
    pub redacted_value: String,
    pub entropy_bps: i64,
    pub is_high_entropy: bool,
    pub is_placeholder: bool,
}

const PLACEHOLDER_MARKERS: &[&str] = &[
    "your_api_key",
    "your-api-key",
    "your_secret",
    "changeme",
    "placeholder",
    "example",
    "dummy",
    "test_key",
    "redacted",
    "insert_here",
    "todo",
    "undefined",
    "null",
    "sample",
];

pub fn is_placeholder_secret(val: &str) -> bool {
    let trimmed = val.trim();
    if trimmed.len() < 6 {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    if PLACEHOLDER_MARKERS.iter().any(|m| lower.contains(m)) {
        return true;
    }
    // Check long repeated character runs like XXXXXXXXXX or AAAAAAAAAA or 00000000
    let mut run = 1usize;
    let bytes = trimmed.as_bytes();
    for i in 1..bytes.len() {
        if bytes[i] == bytes[i - 1] {
            run += 1;
            if run >= 6 {
                return true;
            }
        } else {
            run = 1;
        }
    }
    false
}

pub fn redact_secret(val: &str) -> String {
    let chars: Vec<char> = val.trim().chars().collect();
    if chars.len() <= 8 {
        return "****".to_string();
    }
    let prefix: String = chars[..4].iter().collect();
    let suffix: String = chars[chars.len() - 4..].iter().collect();
    format!("{}****{}", prefix, suffix)
}

/// Evaluates candidate secret/credential values using Shannon Entropy H(X) thresholds:
/// - AWS AKIA keys (20 chars uppercase/digits): >= 3.00 bits/char (300 bps)
/// - General API keys, OpenSSH private keys, passwords, tokens: >= 3.20 bits/char (320 bps)
pub fn evaluate_secret_candidates(text: &str) -> Vec<SecretEval> {
    let mut results = Vec::new();
    let patterns: &[(&str, &str, i64)] = &[
        ("AWS_ACCESS_KEY", r"(AKIA[0-9A-Z]{16})", 300),
        ("GOOGLE_API_KEY", r"(AIza[0-9A-Za-z\-_]{35})", 320),
        ("STRIPE_LIVE_KEY", r"(sk_live_[0-9a-zA-Z]{24,})", 320),
        ("GITHUB_TOKEN", r"(gh[pousr]_[A-Za-z0-9_]{24,})", 320),
        (
            "JWT_TOKEN",
            r"(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})",
            340,
        ),
        (
            "OPENSSH_PRIVATE_KEY",
            r"-----BEGIN OPENSSH PRIVATE KEY-----\s*([A-Za-z0-9+/=\r\n]{24,})",
            320,
        ),
        (
            "KEY_ASSIGNMENT",
            r#"(?i)(?:aws_access_key_id|aws_secret_access_key|secret_key|api_key|private_key|db_password|password|access_token)\s*[:=]\s*["']?([A-Za-z0-9+/=_\-!@#$%^&*]{8,128})["']?"#,
            320,
        ),
    ];

    for &(label, pat, min_bps) in patterns {
        if let Ok(re) = Regex::new(pat) {
            for cap in re.captures_iter(text) {
                if let Some(m) = cap.get(1) {
                    let raw_val = m.as_str().trim();
                    let compact: String = raw_val.chars().filter(|c| !c.is_whitespace()).collect();
                    let bps = shannon_entropy_bps(&compact);
                    let placeholder = is_placeholder_secret(&compact);
                    let high = !placeholder && bps >= min_bps;
                    results.push(SecretEval {
                        matched_key: label.to_string(),
                        redacted_value: redact_secret(&compact),
                        entropy_bps: bps,
                        is_high_entropy: high,
                        is_placeholder: placeholder,
                    });
                }
            }
        }
    }
    results
}
