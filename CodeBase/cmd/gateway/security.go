package main

import "github.com/auxk0rd03/AutoD0rker/gateway/secguard"

func enforceLoopbackAddress(addr string) error {
	return secguard.EnforceLoopbackAddress(addr)
}

func parseTargetInput(rawInput string, allowLocalStaging bool) ([]string, error) {
	return secguard.ParseTargetInput(rawInput, allowLocalStaging)
}

func sanitizeFilename(raw string, fallback string) string {
	return secguard.SanitizeFilename(raw, fallback)
}

func resolveSandboxedPath(baseDir string, parts ...string) (string, error) {
	return secguard.ResolveSandboxedPath(baseDir, parts...)
}

func sanitizeHeaderToken(val string) string {
	return secguard.SanitizeHeaderToken(val)
}
