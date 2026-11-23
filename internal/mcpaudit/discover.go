package mcpaudit

import (
	"os"
	"path/filepath"
	"runtime"
)

// Config discovery (plan D4.1): locate the MCP/agent config files for the common
// clients across macOS/Linux/Windows. Discovery only checks for existence and
// reads files; it never launches anything.

// ClientConfigPaths returns candidate config paths for all known clients, given
// a home dir (and, on Windows, %APPDATA%). Paths may or may not exist.
func ClientConfigPaths(home string) []string {
	var p []string
	join := func(parts ...string) string { return filepath.Join(append([]string{home}, parts...)...) }

	// Claude Code (cross-platform, home-based).
	p = append(p,
		join(".claude.json"),
		join(".claude", "settings.json"),
		join(".claude", "settings.local.json"),
	)
	// Cursor, Windsurf, Zed, Codex, Gemini (home-based).
	p = append(p,
		join(".cursor", "mcp.json"),
		join(".codeium", "windsurf", "mcp_config.json"),
		join(".config", "zed", "settings.json"),
		join(".codex", "config.toml"),
		join(".gemini", "settings.json"),
	)
	// Claude Desktop — platform-specific application-support dir.
	switch runtime.GOOS {
	case "darwin":
		p = append(p, join("Library", "Application Support", "Claude", "claude_desktop_config.json"))
	case "windows":
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			p = append(p, filepath.Join(appdata, "Claude", "claude_desktop_config.json"))
			p = append(p, filepath.Join(appdata, "Code", "User", "mcp.json"))
		}
	default: // linux and others
		p = append(p, join(".config", "Claude", "claude_desktop_config.json"))
		p = append(p, join(".config", "Code", "User", "mcp.json"))
	}
	return p
}

// Discover returns the candidate paths that actually exist.
func Discover(home string) []string {
	var out []string
	for _, p := range ClientConfigPaths(home) {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			out = append(out, p)
		}
	}
	return out
}

// LoadAll parses each path into a Config (JSON configs via ParseMCPJSON; non-JSON
// like config.toml are skipped for now). Returns the configs plus any parse
// errors (keyed by returning them in order; callers may surface or ignore).
func LoadAll(paths []string) ([]Config, []error) {
	var cfgs []Config
	var errs []error
	for _, p := range paths {
		if filepath.Ext(p) != ".json" {
			continue // TOML/other formats not parsed yet
		}
		data, err := os.ReadFile(p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		cfg, err := ParseMCPJSON(p, data)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		cfgs = append(cfgs, cfg)
	}
	return cfgs, errs
}

// AuditHome is the convenience entrypoint: discover configs under home, parse
// them, and run the checks. explicitPath (optional) restricts discovery to a
// single file or directory (for CI / repo scans).
func AuditHome(home, explicitPath string) ([]Finding, []Config) {
	var paths []string
	if explicitPath != "" {
		if fi, err := os.Stat(explicitPath); err == nil {
			if fi.IsDir() {
				_ = filepath.WalkDir(explicitPath, func(path string, d os.DirEntry, err error) error {
					if err == nil && !d.IsDir() && filepath.Ext(path) == ".json" {
						paths = append(paths, path)
					}
					return nil
				})
			} else {
				paths = []string{explicitPath}
			}
		}
	} else {
		paths = Discover(home)
	}
	cfgs, _ := LoadAll(paths)
	return Check(cfgs), cfgs
}
