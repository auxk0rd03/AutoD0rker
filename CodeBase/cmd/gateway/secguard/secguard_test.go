package secguard

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnforceLoopbackAddress(t *testing.T) {
	for _, okAddr := range []string{"127.0.0.1:8090", "[::1]:8090"} {
		if err := EnforceLoopbackAddress(okAddr); err != nil {
			t.Fatalf("expected loopback %q allowed, got %v", okAddr, err)
		}
	}
	for _, badAddr := range []string{"0.0.0.0:8090", "192.168.1.5:8090", "8.8.8.8:8090", "not-an-addr"} {
		if err := EnforceLoopbackAddress(badAddr); err == nil {
			t.Fatalf("expected non-loopback %q rejected", badAddr)
		}
	}
}

func TestIsBlockedIPAndMappedIPv6(t *testing.T) {
	blocked := []string{
		"127.0.0.1",
		"10.1.2.3",
		"172.16.0.1",
		"192.168.0.1",
		"100.64.10.10",
		"169.254.169.254",
		"::1",
		"::ffff:127.0.0.1",
		"::ffff:169.254.169.254",
		"fe80::1",
		"fc00::1",
	}
	for _, s := range blocked {
		if !IsBlockedIP(net.ParseIP(s), false) {
			t.Fatalf("expected IP %s blocked in strict mode", s)
		}
	}
	// Cloud metadata must stay blocked even when allowLocalStaging=true
	if !IsBlockedIP(net.ParseIP("169.254.169.254"), true) {
		t.Fatalf("cloud metadata IP must always be blocked")
	}
	if !IsBlockedIP(net.ParseIP("::ffff:169.254.169.254"), true) {
		t.Fatalf("IPv4-mapped metadata IP must always be blocked")
	}
	// Public IPv4 and IPv6 pass
	if IsBlockedIP(net.ParseIP("93.184.216.34"), false) {
		t.Fatalf("public IPv4 should be allowed")
	}
	if IsBlockedIP(net.ParseIP("2606:4700:4700::1111"), false) {
		t.Fatalf("public IPv6 should be allowed")
	}
}

func TestSanitizeTargetInputAndIPv6(t *testing.T) {
	norm, err := SanitizeTargetInput("https://[2606:4700:4700::1111]/")
	if err != nil {
		t.Fatalf("expected valid public IPv6 URL accepted, got %v", err)
	}
	if norm != "https://[2606:4700:4700::1111]/" {
		t.Fatalf("unexpected IPv6 normalized form: %s", norm)
	}
	if _, err := SanitizeTargetInput("http://example.com;rm -rf /"); err == nil {
		t.Fatalf("expected shell injection rejected")
	}
}

func TestValidateOutboundProxyAndWordlistAndCategories(t *testing.T) {
	publicLookup := func(host string) ([]net.IP, error) {
		if host == "evil.internal" {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		}
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}

	if got, err := ValidateOutboundProxyWithLookup("", false, publicLookup); err != nil || got != "" {
		t.Fatalf("empty proxy should succeed cleanly, got %q %v", got, err)
	}
	if _, err := ValidateOutboundProxyWithLookup("http://127.0.0.1:8080", false, publicLookup); err == nil {
		t.Fatalf("loopback proxy must fail in strict mode")
	}
	if _, err := ValidateOutboundProxyWithLookup("http://127.0.0.1:8080", true, publicLookup); err != nil {
		t.Fatalf("loopback proxy should pass in staging mode: %v", err)
	}
	if _, err := ValidateOutboundProxyWithLookup("http://169.254.169.254:80", true, publicLookup); err == nil {
		t.Fatalf("metadata proxy must always fail")
	}
	gotProxy, err := ValidateOutboundProxyWithLookup("https://proxy.example.org:8443", false, publicLookup)
	if err != nil || gotProxy != "https://proxy.example.org:8443" {
		t.Fatalf("expected clean public proxy URL, got %q err=%v", gotProxy, err)
	}

	wl, err := SanitizeWordlistInput("admin-panel, /.env.prod\n#comment\nsecrets.json")
	if err != nil || len(wl) != 3 || wl[0] != "/admin-panel" {
		t.Fatalf("unexpected wordlist parse: %v err=%v", wl, err)
	}
	if _, err := SanitizeWordlistInput("../../etc/passwd"); err == nil {
		t.Fatalf("traversal in wordlist must be rejected")
	}
	if _, err := SanitizeCategoriesInput("--bad-flag"); err == nil {
		t.Fatalf("CLI flag injection in categories must be rejected")
	}
	cats, err := SanitizeCategoriesInput("Files Containing Passwords, Sensitive Directories")
	if err != nil || !strings.Contains(cats, "Sensitive Directories") {
		t.Fatalf("unexpected categories parse: %q %v", cats, err)
	}
}

func TestResolveSandboxedPathAndHeaderToken(t *testing.T) {
	tmp := t.TempDir()
	safe, err := ResolveSandboxedPath(tmp, "sub", "report.md")
	if err != nil || !strings.HasPrefix(safe, tmp) {
		t.Fatalf("expected sandboxed path inside %s, got %s (%v)", tmp, safe, err)
	}
	if _, err := ResolveSandboxedPath(tmp, "..", "escape"); err == nil {
		t.Fatalf("expected traversal rejected")
	}
	sym := filepath.Join(tmp, "sym")
	if err := os.Symlink(filepath.Join(tmp, "real"), sym); err == nil {
		if _, err := ResolveSandboxedPath(tmp, "sym"); err == nil {
			t.Fatalf("expected symlink rejected (CWE-377)")
		}
	}
	if tok := SanitizeHeaderToken("report\r\nX-Inject: 1"); strings.ContainsAny(tok, "\r\n") {
		t.Fatalf("expected CR/LF stripped, got %q", tok)
	}
	_ = fmt.Sprintf("validated %d", len(safe))
}
