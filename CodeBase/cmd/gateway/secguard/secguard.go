package secguard

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	shellMetaRe = regexp.MustCompile(`[;|&$` + "`" + `()<>\x00\r\n]`)
	hostLabelRe = regexp.MustCompile(`^[a-z0-9.-]+$`)
)

// EnforceLoopbackAddress verifies that the HTTP gateway binds strictly to loopback (127.0.0.1 / ::1).
func EnforceLoopbackAddress(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid bind address %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("SECURITY VIOLATION: gateway must bind strictly to loopback (got %q)", host)
	}
	return nil
}

// IsBlockedIP implements SSRF IP filtering (RFC 1918, loopback, link-local, CGNAT, and cloud metadata).
func IsBlockedIP(ip net.IP, allowLocalStaging bool) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		// Unconditionally block cloud metadata 169.254.169.254 even in local staging mode
		if v4[0] == 169 && v4[1] == 254 && v4[2] == 169 && v4[3] == 254 {
			return true
		}
		if v4.IsLinkLocalUnicast() || v4.IsLinkLocalMulticast() || v4.IsUnspecified() || v4.IsMulticast() {
			return true
		}
		if allowLocalStaging {
			return false
		}
		if v4.IsLoopback() || v4.IsPrivate() {
			return true
		}
		// RFC 6598 CGNAT 100.64.0.0/10
		if v4[0] == 100 && (v4[1]&0xC0) == 64 {
			return true
		}
		return false
	}

	// IPv6 checks
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if allowLocalStaging {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	// Unique Local Address fc00::/7
	if len(ip) == net.IPv6len && (ip[0]&0xFE) == 0xFC {
		return true
	}
	return false
}

// SanitizeTargetInput normalizes and hardens a single target URL token against injection & traversal.
func SanitizeTargetInput(raw string) (string, error) {
	cleaned := strings.TrimSpace(raw)
	cleaned = strings.Trim(cleaned, `"'`)
	cleaned = strings.TrimSpace(cleaned)
	if cleaned == "" {
		return "", fmt.Errorf("empty target URL")
	}
	if shellMetaRe.MatchString(cleaned) || strings.ContainsAny(cleaned, " \t") {
		return "", fmt.Errorf("rejected target %q: prohibited control or shell metacharacters", cleaned)
	}
	if strings.HasPrefix(cleaned, "-") {
		return "", fmt.Errorf("rejected target %q: CLI flag injection prohibited", cleaned)
	}
	if strings.Contains(cleaned, "..") || strings.Contains(cleaned, `\`) {
		return "", fmt.Errorf("rejected target %q: path traversal sequence prohibited", cleaned)
	}

	lower := strings.ToLower(cleaned)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		cleaned = "https://" + cleaned
	}

	u, err := url.Parse(cleaned)
	if err != nil {
		return "", fmt.Errorf("invalid target URL %q: %w", raw, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("rejected scheme %q: only http/https permitted", u.Scheme)
	}
	hostname := strings.ToLower(u.Hostname())
	if hostname == "" || (net.ParseIP(hostname) == nil && !hostLabelRe.MatchString(hostname)) {
		return "", fmt.Errorf("invalid hostname in target %q", raw)
	}

	u.Scheme = scheme
	if port := u.Port(); port != "" {
		u.Host = net.JoinHostPort(hostname, port)
	} else if strings.Contains(hostname, ":") {
		u.Host = "[" + hostname + "]"
	} else {
		u.Host = hostname
	}
	u.Fragment = ""
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}

// ValidateTargetSSRF enforces DNS resolution and IP blocklist validation on a normalized URL.
func ValidateTargetSSRF(normalizedURL string, allowLocalStaging bool) error {
	return ValidateTargetSSRFWithLookup(normalizedURL, allowLocalStaging, net.LookupIP)
}

// ValidateTargetSSRFWithLookup allows deterministic unit testing with a custom DNS resolver.
func ValidateTargetSSRFWithLookup(
	normalizedURL string,
	allowLocalStaging bool,
	lookup func(string) ([]net.IP, error),
) error {
	u, err := url.Parse(normalizedURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return fmt.Errorf("missing hostname")
	}
	if host == "metadata.google.internal" || strings.HasSuffix(host, ".internal") {
		return fmt.Errorf("SSRF blocked: cloud metadata hostname %q is prohibited", host)
	}
	if ip := net.ParseIP(host); ip != nil {
		if IsBlockedIP(ip, allowLocalStaging) {
			return fmt.Errorf("SSRF blocked: target IP %s violates policy", ip.String())
		}
		return nil
	}

	ips, err := lookup(host)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("DNS resolution failed for %q: %v", host, err)
	}
	for _, ip := range ips {
		if IsBlockedIP(ip, allowLocalStaging) {
			return fmt.Errorf("SSRF blocked: %q resolves to prohibited IP %s", host, ip.String())
		}
	}
	return nil
}

// ValidateTargetSSRFForScan allows unresolved external DNS only when routed through a validated outbound proxy.
func ValidateTargetSSRFForScan(
	normalizedURL string,
	allowLocalStaging bool,
	hasProxy bool,
	lookup func(string) ([]net.IP, error),
) error {
	err := ValidateTargetSSRFWithLookup(normalizedURL, allowLocalStaging, lookup)
	if err != nil && hasProxy && strings.HasPrefix(err.Error(), "DNS resolution failed for ") {
		return nil
	}
	return err
}

// ParseTargetInputWithOptions parses target URLs with optional proxy-delegated DNS fallback.
func ParseTargetInputWithOptions(
	rawInput string,
	allowLocalStaging bool,
	hasProxy bool,
	lookup func(string) ([]net.IP, error),
) ([]string, error) {
	if strings.TrimSpace(rawInput) == "" {
		return nil, fmt.Errorf("no target URLs supplied")
	}

	seen := make(map[string]struct{})
	var targets []string

	lines := strings.Split(strings.ReplaceAll(rawInput, "\r\n", "\n"), "\n")
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
			continue
		}
		lowFirst := strings.ToLower(strings.Split(trimmedLine, ",")[0])
		lowFirst = strings.TrimSpace(strings.Trim(lowFirst, `"'`))
		if lowFirst == "domain" || lowFirst == "url" || lowFirst == "target" || lowFirst == "target_url" || lowFirst == "host" {
			continue
		}
		parts := strings.Split(trimmedLine, ",")
		for _, part := range parts {
			candidate := strings.TrimSpace(part)
			if candidate == "" {
				continue
			}
			norm, err := SanitizeTargetInput(candidate)
			if err != nil {
				return nil, err
			}
			if err := ValidateTargetSSRFForScan(norm, allowLocalStaging, hasProxy, lookup); err != nil {
				return nil, err
			}
			if _, ok := seen[norm]; !ok {
				seen[norm] = struct{}{}
				targets = append(targets, norm)
			}
		}
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid target URLs extracted")
	}
	return targets, nil
}

// ParseTargetInput parses single URL, comma-separated lists, or CSV src_list uploads,
// enforcing sanitization, order-preserving deduplication, and SSRF validation.
func ParseTargetInput(rawInput string, allowLocalStaging bool) ([]string, error) {
	return ParseTargetInputWithLookup(rawInput, allowLocalStaging, net.LookupIP)
}

// ParseTargetInputWithLookup performs target parsing using an injected DNS lookup function.
func ParseTargetInputWithLookup(
	rawInput string,
	allowLocalStaging bool,
	lookup func(string) ([]net.IP, error),
) ([]string, error) {
	return ParseTargetInputWithOptions(rawInput, allowLocalStaging, false, lookup)
}

// SanitizeFilename prevents directory traversal and control-character filenames (CWE-22).
func SanitizeFilename(raw string, fallback string) string {
	base := filepath.Base(strings.TrimSpace(raw))
	base = strings.ReplaceAll(base, "\x00", "")
	base = strings.TrimLeft(base, ".")
	var b strings.Builder
	for _, r := range base {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	res := b.String()
	if res == "" {
		return fallback
	}
	return res
}

// ResolveSandboxedPath validates that joined path components stay strictly within baseDir with zero symlinks (CWE-377).
func ResolveSandboxedPath(baseDir string, parts ...string) (string, error) {
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", err
	}
	joined := absBase
	for _, p := range parts {
		if strings.Contains(p, "\x00") || strings.Contains(p, "..") {
			return "", fmt.Errorf("path traversal rejected in %q", p)
		}
		joined = filepath.Join(joined, p)
	}
	absTarget, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(absBase, absTarget)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("sandbox escape rejected: %q outside %q", absTarget, absBase)
	}
	if info, statErr := os.Lstat(absTarget); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("CWE-377 symlink rejected at %q", absTarget)
		}
	}
	return absTarget, nil
}

// SanitizeHeaderToken strips CR/LF/NUL characters to prevent HTTP header injection.
func SanitizeHeaderToken(val string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(val) {
		if r != '\r' && r != '\n' && r != '\x00' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ValidateOutboundProxy validates an optional upstream HTTP/HTTPS proxy URL against injection & SSRF rules.
func ValidateOutboundProxy(rawProxy string, allowLocalStaging bool) (string, error) {
	return ValidateOutboundProxyWithLookup(rawProxy, allowLocalStaging, net.LookupIP)
}

// ValidateOutboundProxyWithLookup validates an outbound proxy URL using an injectable DNS lookup function.
func ValidateOutboundProxyWithLookup(
	rawProxy string,
	allowLocalStaging bool,
	lookup func(string) ([]net.IP, error),
) (string, error) {
	cleaned := strings.TrimSpace(rawProxy)
	if cleaned == "" {
		return "", nil
	}
	if shellMetaRe.MatchString(cleaned) || strings.ContainsAny(cleaned, " \t") || strings.HasPrefix(cleaned, "-") {
		return "", fmt.Errorf("rejected proxy URL %q: prohibited characters", cleaned)
	}
	if !strings.HasPrefix(strings.ToLower(cleaned), "http://") && !strings.HasPrefix(strings.ToLower(cleaned), "https://") {
		return "", fmt.Errorf("proxy URL %q must use http:// or https:// scheme", cleaned)
	}
	u, err := url.Parse(cleaned)
	if err != nil {
		return "", fmt.Errorf("invalid proxy URL %q: %w", rawProxy, err)
	}
	if u.Hostname() == "" || u.Port() == "" {
		return "", fmt.Errorf("proxy URL %q must include host and port", rawProxy)
	}
	if err := ValidateTargetSSRFWithLookup(u.String(), allowLocalStaging, lookup); err != nil {
		return "", fmt.Errorf("proxy SSRF validation failed: %w", err)
	}
	u.Fragment = ""
	u.RawQuery = ""
	return u.String(), nil
}

// SanitizeWordlistInput parses user-supplied custom probe paths with strict traversal & injection guards.
func SanitizeWordlistInput(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var out []string
	seen := make(map[string]struct{})
	normalized := strings.NewReplacer("\r\n", "\n", ",", "\n").Replace(raw)
	for _, entry := range strings.Split(normalized, "\n") {
		token := strings.TrimSpace(entry)
		if token == "" || strings.HasPrefix(token, "#") {
			continue
		}
		if shellMetaRe.MatchString(token) || strings.Contains(token, "..") || strings.Contains(token, `\`) || strings.ContainsAny(token, " \t") {
			return nil, fmt.Errorf("rejected unsafe wordlist path %q", token)
		}
		if !strings.HasPrefix(token, "/") {
			token = "/" + token
		}
		if len(token) > 128 {
			return nil, fmt.Errorf("wordlist path exceeds 128 chars: %q", token)
		}
		if _, ok := seen[token]; !ok {
			seen[token] = struct{}{}
			out = append(out, token)
			if len(out) >= 128 {
				break
			}
		}
	}
	return out, nil
}

// SanitizeCategoriesInput cleans comma-separated dork category filters and blocks injection characters.
func SanitizeCategoriesInput(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	var clean []string
	for _, part := range strings.Split(raw, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		if shellMetaRe.MatchString(p) || strings.HasPrefix(p, "-") {
			return "", fmt.Errorf("rejected unsafe category filter %q", p)
		}
		clean = append(clean, p)
	}
	return strings.Join(clean, ","), nil
}
