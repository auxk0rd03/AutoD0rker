package tests

import "testing"

func TestParseTargetInputMultiAndCSV(t *testing.T) {
	VerifyParseTargetInputMultiAndCSV(t)
}

func TestInputInjectionRejected(t *testing.T) {
	VerifyInputInjectionRejected(t)
}

func TestSSRFBlockingRFC1918AndMetadata(t *testing.T) {
	VerifySSRFBlockingRFC1918AndMetadata(t)
}

func TestSandboxedPathRejectsTraversalAndSymlinks(t *testing.T) {
	VerifySandboxedPathRejectsTraversalAndSymlinks(t)
}
