// Package trishul is the module root. It embeds the rule-metadata catalog so any
// binary (the CLI, the MCP server) can load it without the rules/ directory being
// present on disk at runtime — which keeps Trishul a single, self-contained,
// local-first binary.
package trishul

import (
	"embed"

	"github.com/Armur-Ai/Trishul/internal/rules"
)

//go:embed rules/*.yaml
var rulesFS embed.FS

// RulesFS exposes the embedded rule catalog files (rules/*.yaml).
func RulesFS() embed.FS { return rulesFS }

// Catalog loads the embedded rule-metadata catalog.
func Catalog() (*rules.Catalog, error) {
	return rules.LoadCatalogFS(rulesFS, "rules")
}
