package main

import (
	"net"

	"github.com/auxk0rd03/AutoD0rker/gateway/cmd/gateway/secguard"
)

func enforceLoopbackAddress(addr string) error {
	return secguard.EnforceLoopbackAddress(addr)
}

func parseTargetInputWithProxy(rawInput string, allowLocalStaging bool, hasProxy bool) ([]string, error) {
	return secguard.ParseTargetInputWithOptions(rawInput, allowLocalStaging, hasProxy, net.LookupIP)
}

func validateOutboundProxy(rawProxy string, allowLocalStaging bool) (string, error) {
	return secguard.ValidateOutboundProxy(rawProxy, allowLocalStaging)
}

func sanitizeWordlistInput(raw string) ([]string, error) {
	return secguard.SanitizeWordlistInput(raw)
}

func sanitizeCategoriesInput(raw string) (string, error) {
	return secguard.SanitizeCategoriesInput(raw)
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
