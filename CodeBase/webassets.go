package webassets

import "embed"

// EmbeddedWebFS bundles web/templates and web/static into the standalone gateway binary (P2 #10).
//
//go:embed all:web
var EmbeddedWebFS embed.FS
