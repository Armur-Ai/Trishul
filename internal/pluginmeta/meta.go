// Package pluginmeta locates and validates the Claude Code plugin and
// plugin-marketplace manifests that ship under plugins/claude-code/ and
// packaging/claude-marketplace/. It exists so `go test ./...` fails fast if one
// of those hand-maintained JSON files becomes malformed or loses a required key.
package pluginmeta

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

// Manifest paths, relative to the repository root.
const (
	PluginManifestPath = "plugins/claude-code/.claude-plugin/plugin.json"
	PluginHooksPath    = "plugins/claude-code/hooks/hooks.json"
	PluginMCPPath      = "plugins/claude-code/.mcp.json"
	MarketplacePath    = "packaging/claude-marketplace/marketplace.json"
)

// RepoRoot returns the Trishul repo root, resolved relative to this source file
// (internal/pluginmeta/meta.go is two directories below the root).
func RepoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// LoadJSON reads a repo-root-relative JSON file and unmarshals it into a map.
func LoadJSON(rel string) (map[string]any, error) {
	b, err := os.ReadFile(filepath.Join(RepoRoot(), rel))
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}
