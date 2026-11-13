package main

import (
	"net"
	"testing"

	"github.com/auxk0rd03/AutoD0rker/gateway/secguard"
)

func TestLoopbackEnforcement(t *testing.T) {
	if err := enforceLoopbackAddress("127.0.0.1:8090"); err != nil {
		t.Fatalf("expected 127.0.0.1 to pass: %v", err)
	}
	if err := enforceLoopbackAddress("0.0.0.0:8090"); err == nil {
		t.Fatalf("expected 0.0.0.0 to be rejected")
	}
}

func TestParseAndSSRFGuards(t *testing.T) {
	stubPublic := func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}
	targets, err := secguard.ParseTargetInputWithLookup("https://example.com, app.example.com, https://example.com", false, stubPublic)
	if err != nil || len(targets) != 2 {
		t.Fatalf("unexpected parse result: %v %v", targets, err)
	}
}
