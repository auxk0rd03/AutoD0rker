package tests

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/auxk0rd03/AutoD0rker/gateway/cmd/gateway/secguard"
)

func VerifyParseTargetInputMultiAndCSV(t *testing.T) {
	publicLookup := func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}

	raw := "domain\nhttps://portal.example.org/#frag, app2.example.org\nhttps://portal.example.org\n"
	targets, err := secguard.ParseTargetInputWithLookup(raw, false, publicLookup)
	if err != nil {
		t.Fatalf("expected valid target parsing, got error: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 deduplicated targets, got %d (%v)", len(targets), targets)
	}
	if targets[0] != "https://portal.example.org/" || targets[1] != "https://app2.example.org/" {
		t.Fatalf("unexpected normalization: %v", targets)
	}
}

func VerifyInputInjectionRejected(t *testing.T) {
	malicious := []string{
		"https://example.com;rm -rf /",
		"https://example.com|id",
		"-oProxyCommand=id",
		"https://example.com/../../etc/passwd",
		"javascript:alert(1)",
	}
	for _, m := range malicious {
		if _, err := secguard.SanitizeTargetInput(m); err == nil {
			t.Fatalf("expected injection input %q to be rejected", m)
		}
	}
}

func VerifySSRFBlockingRFC1918AndMetadata(t *testing.T) {
	privCases := []struct {
		host string
		ip   string
	}{
		{"internal-10.example.com", "10.12.0.5"},
		{"internal-172.example.com", "172.16.42.9"},
		{"internal-192.example.com", "192.168.1.50"},
		{"loopback.example.com", "127.0.0.1"},
		{"cgnat.example.com", "100.64.0.1"},
		{"meta.example.com", "169.254.169.254"},
	}

	for _, tc := range privCases {
		lookup := func(string) ([]net.IP, error) {
			return []net.IP{net.ParseIP(tc.ip)}, nil
		}
		if _, err := secguard.ParseTargetInputWithLookup("https://"+tc.host, false, lookup); err == nil {
			t.Fatalf("expected SSRF block for %s (%s)", tc.host, tc.ip)
		}
	}

	localLookup := func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	if _, err := secguard.ParseTargetInputWithLookup("http://127.0.0.1:8080", true, localLookup); err != nil {
		t.Fatalf("expected local staging to allow loopback: %v", err)
	}

	metaLookup := func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("169.254.169.254")}, nil
	}
	if _, err := secguard.ParseTargetInputWithLookup("http://169.254.169.254/latest/meta-data", true, metaLookup); err == nil {
		t.Fatalf("cloud metadata IP must NEVER be allowed even with local staging enabled")
	}
	if _, err := secguard.ParseTargetInputWithLookup("http://metadata.google.internal/", true, localLookup); err == nil {
		t.Fatalf("metadata.google.internal must NEVER be allowed")
	}
}

func VerifySandboxedPathRejectsTraversalAndSymlinks(t *testing.T) {
	base := t.TempDir()
	if _, err := secguard.ResolveSandboxedPath(base, "..", "escape"); err == nil {
		t.Fatalf("expected path traversal to be blocked")
	}
	realFile := filepath.Join(base, "real.txt")
	_ = os.WriteFile(realFile, []byte("ok"), 0600)
	symFile := filepath.Join(base, "link.txt")
	if err := os.Symlink(realFile, symFile); err == nil {
		if _, err2 := secguard.ResolveSandboxedPath(base, "link.txt"); err2 == nil {
			t.Fatalf("expected CWE-377 symlink rejection")
		}
	}
}
