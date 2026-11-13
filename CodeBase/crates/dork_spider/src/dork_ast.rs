use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DorkOperator {
    InUrl(String),
    InTitle(String),
    InText(String),
    FileType(String),
    Site(String),
    ExactPhrase(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DorkExpr {
    Term(DorkOperator),
    Not(Box<DorkExpr>),
    And(Vec<DorkExpr>),
    Or(Vec<DorkExpr>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledDorkRule {
    pub rule_id: i64,
    pub category: String,
    pub is_chain: bool,
    pub raw_dork: String,
    pub notes: String,
    pub default_severity: String,
    pub cwe_id: String,
    pub expr_tree: DorkExpr,
    pub candidate_probe_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    LParen,
    RParen,
    Pipe,
    Amp,
    OrWord,
    AndWord,
    Minus,
    Plus,
    Comma,
    Operator(String, String),
    Quoted(String),
    Word(String),
}

fn is_operator_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "inurl"
            | "allinurl"
            | "intitle"
            | "allintitle"
            | "intext"
            | "allintext"
            | "ext"
            | "filetype"
            | "site"
    )
}

fn read_quoted(chars: &[char], idx: &mut usize, quote: char) -> String {
    *idx += 1; // skip opening quote
    let mut out = String::new();
    while *idx < chars.len() {
        let ch = chars[*idx];
        if ch == quote {
            *idx += 1;
            break;
        }
        // Gracefully recover from mismatched quotes seen in legacy GHDB entries (e.g. 'Sypex Dumper")
        if (quote == '\'' && ch == '"') && out.len() > 2 {
            *idx += 1;
            break;
        }
        out.push(ch);
        *idx += 1;
    }
    out
}

fn read_unquoted_value(chars: &[char], idx: &mut usize) -> String {
    let mut out = String::new();
    let mut paren_depth = 0usize;
    while *idx < chars.len() {
        let ch = chars[*idx];
        if ch.is_whitespace() || ch == '|' || ch == '&' {
            break;
        }
        if ch == '(' {
            paren_depth += 1;
        } else if ch == ')' {
            if paren_depth == 0 {
                break;
            }
            paren_depth -= 1;
        }
        out.push(ch);
        *idx += 1;
    }
    out
}

fn tokenize_dork(raw: &str) -> Vec<Token> {
    let chars: Vec<char> = raw.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];
        if ch.is_whitespace() {
            i += 1;
            continue;
        }
        match ch {
            '(' => {
                tokens.push(Token::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                i += 1;
            }
            '|' => {
                tokens.push(Token::Pipe);
                i += 1;
            }
            '&' => {
                tokens.push(Token::Amp);
                i += 1;
            }
            '+' => {
                tokens.push(Token::Plus);
                i += 1;
            }
            ',' => {
                tokens.push(Token::Comma);
                i += 1;
            }
            '-' => {
                // Distinguish unary exclusion from hyphenated tokens
                let prev_is_delim = i == 0
                    || chars[i - 1].is_whitespace()
                    || matches!(chars[i - 1], '(' | '|' | '&' | ',');
                let next_is_nonspace = i + 1 < chars.len() && !chars[i + 1].is_whitespace();
                if prev_is_delim && next_is_nonspace {
                    tokens.push(Token::Minus);
                    i += 1;
                } else {
                    let word = read_unquoted_value(&chars, &mut i);
                    if !word.is_empty() {
                        tokens.push(Token::Word(word));
                    }
                }
            }
            '"' | '\'' => {
                let s = read_quoted(&chars, &mut i, ch);
                if !s.is_empty() {
                    tokens.push(Token::Quoted(s));
                }
            }
            _ => {
                // Check for legacy "index of:" / "Indexof:" pattern
                let rest: String = chars[i..].iter().collect();
                let lower_rest = rest.to_ascii_lowercase();
                if lower_rest.starts_with("index of:") {
                    i += "index of:".len();
                    while i < chars.len() && chars[i].is_whitespace() {
                        i += 1;
                    }
                    tokens.push(Token::Operator(
                        "intitle".to_string(),
                        "index of".to_string(),
                    ));
                    continue;
                }
                if lower_rest.starts_with("indexof:") {
                    i += "indexof:".len();
                    while i < chars.len() && chars[i].is_whitespace() {
                        i += 1;
                    }
                    tokens.push(Token::Operator(
                        "intitle".to_string(),
                        "index of".to_string(),
                    ));
                    continue;
                }

                // Read until whitespace, delimiter, or ':'
                let start = i;
                while i < chars.len()
                    && !chars[i].is_whitespace()
                    && !matches!(chars[i], '(' | ')' | '|' | '&' | ',' | ':')
                {
                    i += 1;
                }
                let head: String = chars[start..i].iter().collect();

                if i < chars.len() && chars[i] == ':' && is_operator_name(&head) {
                    i += 1; // consume ':'
                    while i < chars.len() && chars[i].is_whitespace() {
                        i += 1;
                    }
                    if i >= chars.len() {
                        // Trailing empty operator like `allinurl:` in malformed GHDB rows
                        continue;
                    }
                    let val = if chars[i] == '"' || chars[i] == '\'' {
                        let q = chars[i];
                        read_quoted(&chars, &mut i, q)
                    } else if chars[i] == '(' {
                        // e.g. inurl:(resume|cv) -> keep parenthesized expression after operator?
                        // Emit operator markers inside parser by returning empty marker or handling below
                        "".to_string()
                    } else {
                        let first = read_unquoted_value(&chars, &mut i);
                        // Handle unquoted `intitle:index of /etc/ssh` or `intitle: index of "awstats"`
                        if head.eq_ignore_ascii_case("intitle")
                            && first.eq_ignore_ascii_case("index")
                        {
                            let saved = i;
                            let mut probe = i;
                            while probe < chars.len() && chars[probe].is_whitespace() {
                                probe += 1;
                            }
                            let next_word = read_unquoted_value(&chars, &mut probe);
                            if next_word.eq_ignore_ascii_case("of") {
                                i = probe;
                                let mut combined = "index of".to_string();
                                let mut probe2 = i;
                                while probe2 < chars.len() && chars[probe2].is_whitespace() {
                                    probe2 += 1;
                                }
                                if probe2 < chars.len() && chars[probe2] == '/' {
                                    let path_part = read_unquoted_value(&chars, &mut probe2);
                                    if !path_part.is_empty() {
                                        combined.push(' ');
                                        combined.push_str(&path_part);
                                        i = probe2;
                                    }
                                }
                                combined
                            } else {
                                i = saved;
                                first
                            }
                        } else {
                            first
                        }
                    };

                    if val.is_empty() && i < chars.len() && chars[i] == '(' {
                        // Case like `inurl:(resume|cv)` -> distribute operator across group
                        i += 1;
                        let mut group_str = String::new();
                        while i < chars.len() && chars[i] != ')' {
                            group_str.push(chars[i]);
                            i += 1;
                        }
                        if i < chars.len() && chars[i] == ')' {
                            i += 1;
                        }
                        tokens.push(Token::LParen);
                        for (idx_part, part) in group_str.split('|').enumerate() {
                            if idx_part > 0 {
                                tokens.push(Token::Pipe);
                            }
                            let trimmed = part.trim().trim_matches('"').trim_matches('\'');
                            if !trimmed.is_empty() {
                                tokens.push(Token::Operator(
                                    head.to_ascii_lowercase(),
                                    trimmed.to_string(),
                                ));
                            }
                        }
                        tokens.push(Token::RParen);
                    } else if !val.is_empty() {
                        tokens.push(Token::Operator(head.to_ascii_lowercase(), val));
                    }
                } else {
                    // Could be `OR`, `AND`, or a bare word / URL fragment containing ':' (e.g. `:8080/`)
                    let mut full = head;
                    if i < chars.len() && chars[i] == ':' {
                        full.push(':');
                        i += 1;
                        full.push_str(&read_unquoted_value(&chars, &mut i));
                    }
                    if full == "OR" {
                        tokens.push(Token::OrWord);
                    } else if full == "AND" {
                        tokens.push(Token::AndWord);
                    } else if !full.is_empty() {
                        tokens.push(Token::Word(full));
                    }
                }
            }
        }
    }

    tokens
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn bump(&mut self) -> Option<Token> {
        if self.pos < self.tokens.len() {
            let tok = self.tokens[self.pos].clone();
            self.pos += 1;
            Some(tok)
        } else {
            None
        }
    }

    fn parse_top(&mut self) -> DorkExpr {
        let expr = self.parse_or_top();
        expr
    }

    fn parse_or_top(&mut self) -> DorkExpr {
        let mut branches = Vec::new();
        branches.push(self.parse_and());

        while matches!(
            self.peek(),
            Some(Token::Pipe | Token::OrWord | Token::Comma)
        ) {
            self.bump();
            if matches!(self.peek(), None | Some(Token::RParen)) {
                break;
            }
            branches.push(self.parse_and());
        }

        simplify_or(branches)
    }

    fn parse_and(&mut self) -> DorkExpr {
        let mut terms = Vec::new();
        while let Some(tok) = self.peek() {
            match tok {
                Token::RParen | Token::Pipe | Token::OrWord | Token::Comma => break,
                Token::Amp | Token::AndWord | Token::Plus => {
                    self.bump();
                    continue;
                }
                _ => {
                    if let Some(unit) = self.parse_pipe_unit() {
                        terms.push(unit);
                    } else {
                        break;
                    }
                }
            }
        }
        simplify_and(terms)
    }

    // Handles tight `|` / `OR` between atomic unary terms (e.g. `site:.com inurl:login | inurl:logon`)
    // while yielding to top-level `|` when following a parenthesized group `( ... )`.
    fn parse_pipe_unit(&mut self) -> Option<DorkExpr> {
        let starts_with_paren = matches!(self.peek(), Some(Token::LParen));
        let first = self.parse_unary()?;
        if starts_with_paren {
            return Some(first);
        }

        let mut alts = vec![first];
        while matches!(self.peek(), Some(Token::Pipe | Token::OrWord)) {
            // If next after pipe is LParen, let top-level OR handle `(A) | (B)`
            if matches!(self.tokens.get(self.pos + 1), Some(Token::LParen)) {
                break;
            }
            self.bump();
            if let Some(next_u) = self.parse_unary() {
                alts.push(next_u);
            } else {
                break;
            }
        }
        Some(simplify_or(alts))
    }

    fn parse_unary(&mut self) -> Option<DorkExpr> {
        match self.peek()?.clone() {
            Token::Minus => {
                self.bump();
                let inner = self.parse_primary()?;
                // Bare TLD exclusions like `-com`, `-net`, `-in` map to Site exclusion
                let normalized = match inner {
                    DorkExpr::Term(DorkOperator::ExactPhrase(ref s))
                        if matches!(
                            s.as_str(),
                            "com"
                                | "net"
                                | "org"
                                | "in"
                                | "aws"
                                | "litespeed"
                                | "LiteSpeed"
                                | "oracle"
                        ) =>
                    {
                        if s.eq_ignore_ascii_case("com")
                            || s.eq_ignore_ascii_case("net")
                            || s.eq_ignore_ascii_case("org")
                            || s.eq_ignore_ascii_case("in")
                        {
                            DorkExpr::Term(DorkOperator::Site(format!(
                                ".{}",
                                s.to_ascii_lowercase()
                            )))
                        } else {
                            inner
                        }
                    }
                    other => other,
                };
                Some(DorkExpr::Not(Box::new(normalized)))
            }
            _ => self.parse_primary(),
        }
    }

    fn parse_primary(&mut self) -> Option<DorkExpr> {
        let tok = self.peek()?.clone();
        match tok {
            Token::LParen => {
                self.bump();
                let inner = self.parse_or_top();
                if matches!(self.peek(), Some(Token::RParen)) {
                    self.bump();
                }
                Some(inner)
            }
            Token::Operator(op, val) => {
                self.bump();
                Some(DorkExpr::Term(map_operator(&op, &val)))
            }
            Token::Quoted(s) => {
                self.bump();
                Some(DorkExpr::Term(DorkOperator::ExactPhrase(s)))
            }
            Token::Word(w) => {
                self.bump();
                if w.starts_with('/') && w.contains('.') {
                    Some(DorkExpr::Term(DorkOperator::InUrl(w)))
                } else {
                    Some(DorkExpr::Term(DorkOperator::ExactPhrase(w)))
                }
            }
            Token::RParen | Token::Pipe | Token::OrWord | Token::Comma => None,
            Token::Amp | Token::AndWord | Token::Plus | Token::Minus => {
                self.bump();
                self.parse_primary()
            }
        }
    }
}

fn map_operator(op: &str, val: &str) -> DorkOperator {
    match op {
        "inurl" | "allinurl" => DorkOperator::InUrl(val.to_string()),
        "intitle" | "allintitle" => DorkOperator::InTitle(val.to_string()),
        "intext" | "allintext" => DorkOperator::InText(val.to_string()),
        "ext" | "filetype" => DorkOperator::FileType(val.trim_start_matches('.').to_string()),
        "site" => DorkOperator::Site(val.to_string()),
        _ => DorkOperator::ExactPhrase(val.to_string()),
    }
}

fn simplify_and(items: Vec<DorkExpr>) -> DorkExpr {
    let mut flat = Vec::new();
    for item in items {
        match item {
            DorkExpr::And(sub) => flat.extend(sub),
            other => flat.push(other),
        }
    }
    match flat.len() {
        0 => DorkExpr::Term(DorkOperator::ExactPhrase(String::new())),
        1 => flat.into_iter().next().unwrap(),
        _ => DorkExpr::And(flat),
    }
}

fn simplify_or(items: Vec<DorkExpr>) -> DorkExpr {
    let mut flat = Vec::new();
    for item in items {
        match item {
            DorkExpr::Or(sub) => flat.extend(sub),
            other => flat.push(other),
        }
    }
    match flat.len() {
        0 => DorkExpr::Term(DorkOperator::ExactPhrase(String::new())),
        1 => flat.into_iter().next().unwrap(),
        _ => DorkExpr::Or(flat),
    }
}

pub fn parse_dork_string(raw: &str) -> DorkExpr {
    let tokens = tokenize_dork(raw);
    if tokens.is_empty() {
        return DorkExpr::Term(DorkOperator::ExactPhrase(raw.trim().to_string()));
    }
    let mut parser = Parser::new(tokens);
    parser.parse_top()
}

pub fn synthesize_probe_paths(expr: &DorkExpr) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    collect_probes(expr, false, &mut seen, &mut out);
    out
}

fn push_probe(path: String, seen: &mut HashSet<String>, out: &mut Vec<String>) {
    let trimmed = path.trim();
    if trimmed.is_empty()
        || trimmed.contains('*')
        || trimmed.contains(' ')
        || trimmed.contains('?')
        || trimmed.contains(':')
        || trimmed.len() > 96
    {
        return;
    }
    let normalized = if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{}", trimmed)
    };
    if normalized == "/" || normalized == "/." || normalized.contains("..") {
        return;
    }
    if seen.insert(normalized.clone()) {
        out.push(normalized);
    }
}

fn collect_probes(
    expr: &DorkExpr,
    negated: bool,
    seen: &mut HashSet<String>,
    out: &mut Vec<String>,
) {
    if negated {
        return;
    }
    match expr {
        DorkExpr::Not(inner) => collect_probes(inner, true, seen, out),
        DorkExpr::And(list) | DorkExpr::Or(list) => {
            for item in list {
                collect_probes(item, false, seen, out);
            }
        }
        DorkExpr::Term(op) => match op {
            DorkOperator::InUrl(val) => {
                let v = val.trim().trim_matches('"');
                if v.contains('/') || v.contains('.') {
                    push_probe(v.to_string(), seen, out);
                } else if matches!(
                    v.to_ascii_lowercase().as_str(),
                    "login" | "admin" | "adminpanel" | "api-docs" | "swagger" | "env"
                ) {
                    push_probe(format!("/{}", v), seen, out);
                }
            }
            DorkOperator::InTitle(val) => {
                let lower = val.to_ascii_lowercase();
                if let Some(idx) = lower.find("index of /") {
                    let sub = val[idx + "index of ".len()..].trim();
                    if sub.len() > 1 && !sub.contains('*') {
                        push_probe(sub.to_string(), seen, out);
                    }
                }
            }
            DorkOperator::ExactPhrase(val) => {
                let v = val.trim();
                // File names / paths explicitly referenced in index-of or config dorks
                let looks_like_file = (v.starts_with('/') && v.len() > 1)
                    || (v.contains('.')
                        && !v.contains(' ')
                        && [
                            ".conf", ".yaml", ".yml", ".json", ".env", ".sql", ".txt", ".php",
                            ".bak", ".old", ".log", ".xml", ".zip", ".sh", ".aspx", ".jsp",
                        ]
                        .iter()
                        .any(|ext| {
                            v.to_ascii_lowercase().ends_with(ext) || v == ".env" || v == ".git"
                        }));
                if looks_like_file
                    && !v.ends_with(".com")
                    && !v.ends_with(".net")
                    && !v.ends_with(".org")
                {
                    push_probe(v.to_string(), seen, out);
                }
            }
            DorkOperator::FileType(ext) => match ext.to_ascii_lowercase().as_str() {
                "env" => push_probe("/.env".to_string(), seen, out),
                "sql" => push_probe("/database.sql".to_string(), seen, out),
                _ => {}
            },
            _ => {}
        },
    }
}

pub fn classify_dork_rule(category: &str, raw_dork: &str) -> (&'static str, &'static str) {
    let cat_lower = category.to_ascii_lowercase();
    let dork_lower = raw_dork.to_ascii_lowercase();

    if cat_lower.contains("passwords")
        || dork_lower.contains("begin openssh private key")
        || dork_lower.contains("aws_access_key_id")
        || dork_lower.contains("aws_secret_access_key")
        || dork_lower.contains("/etc/shadow")
        || dork_lower.contains("private_key.pem")
    {
        return ("CRITICAL", "CWE-798");
    }

    if dork_lower.contains(".env")
        || dork_lower.contains("wp-config")
        || dork_lower.contains("database.sql")
        || dork_lower.contains(".git")
        || dork_lower.contains(".ssh")
        || dork_lower.contains("configmap.yaml")
        || dork_lower.contains("access_token.json")
        || dork_lower.contains("phpinfo")
        || cat_lower.contains("vulnerable servers")
        || cat_lower.contains("advisories")
    {
        return ("HIGH", "CWE-538");
    }

    if cat_lower.contains("sensitive directories") || dork_lower.contains("index of") {
        return ("MEDIUM", "CWE-538");
    }

    if cat_lower.contains("login portals") {
        return ("MEDIUM", "CWE-287");
    }

    if cat_lower.contains("online devices") {
        return ("MEDIUM", "CWE-16");
    }

    ("MEDIUM", "CWE-200")
}

pub fn load_dorkset_csv(csv_path: &Path) -> Result<Vec<CompiledDorkRule>, String> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_path(csv_path)
        .map_err(|e| format!("Failed to open DorkSet CSV {:?}: {}", csv_path, e))?;

    let mut rules = Vec::new();
    for (idx, result) in reader.records().enumerate() {
        let record = result.map_err(|e| format!("CSV parse error at row {}: {}", idx + 2, e))?;
        let category = record.get(0).unwrap_or("").trim().to_string();
        let raw_dork = record.get(1).unwrap_or("").trim().to_string();
        let notes = record.get(2).unwrap_or("").trim().to_string();
        if category.is_empty() || raw_dork.is_empty() {
            continue;
        }
        let is_chain = category.starts_with("[CHAIN]");
        let expr_tree = parse_dork_string(&raw_dork);
        let candidate_probe_paths = synthesize_probe_paths(&expr_tree);
        let (default_severity, cwe_id) = classify_dork_rule(&category, &raw_dork);

        rules.push(CompiledDorkRule {
            rule_id: (idx + 1) as i64,
            category,
            is_chain,
            raw_dork,
            notes,
            default_severity: default_severity.to_string(),
            cwe_id: cwe_id.to_string(),
            expr_tree,
            candidate_probe_paths,
        });
    }

    Ok(rules)
}
