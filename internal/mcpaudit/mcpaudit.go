// Package mcpaudit audits a developer's AI setup — the MCP servers, tokens and
// permissions configured across Claude/Cursor/Windsurf/etc. (plan D4). It parses
// the various config shapes into a normalized model and runs security checks
// (unpinned servers, plaintext tokens, overbroad permissions, insecure remote
// servers, shadowed tool names). Hermetic: it only reads config files and never
// launches a server.
package mcpaudit

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/Armur-Ai/Trishul/internal/redact"
)

// Server is one configured MCP server, normalized across client formats.
type Server struct {
	Name    string
	Command string
	Args    []string
	URL     string
	Env     map[string]string
	Source  string // which config file it came from
}

// Config is one client's parsed MCP configuration.
type Config struct {
	Source      string
	Servers     []Server
	Permissions []string // allowlist entries, bypass flags, etc.
}

// Finding is one audit result.
type Finding struct {
	CheckID  string
	Severity string // CRITICAL/HIGH/MEDIUM/LOW
	Title    string
	Server   string
	Detail   string
	Fix      string
}

// ParseMCPJSON parses the common `{ "mcpServers": { name: {command,args,env,url} } }`
// shape (Claude/Cursor/VS Code). Unknown fields are ignored.
func ParseMCPJSON(source string, data []byte) (Config, error) {
	var raw struct {
		MCPServers map[string]struct {
			Command string            `json:"command"`
			Args    []string          `json:"args"`
			URL     string            `json:"url"`
			Env     map[string]string `json:"env"`
		} `json:"mcpServers"`
		Permissions struct {
			Allow       []string `json:"allow"`
			DefaultMode string   `json:"defaultMode"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return Config{}, err
	}
	cfg := Config{Source: source}
	names := make([]string, 0, len(raw.MCPServers))
	for n := range raw.MCPServers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		s := raw.MCPServers[n]
		cfg.Servers = append(cfg.Servers, Server{
			Name: n, Command: s.Command, Args: s.Args, URL: s.URL, Env: s.Env, Source: source,
		})
	}
	cfg.Permissions = append(cfg.Permissions, raw.Permissions.Allow...)
	if raw.Permissions.DefaultMode != "" {
		cfg.Permissions = append(cfg.Permissions, "defaultMode:"+raw.Permissions.DefaultMode)
	}
	return cfg, nil
}

var (
	reVersioned   = regexp.MustCompile(`@[0-9]`) // pkg@1.2.3
	reProviderKey = regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]{10,}`)
	rePlaceholder = regexp.MustCompile(`(?i)^(your[_-]|<.*>$|xxx+|changeme|\$\{?[A-Z_]+\}?$|example)`)
)

// Check runs every audit check over the configs and returns sorted findings.
func Check(cfgs []Config) []Finding {
	var out []Finding
	seenName := map[string]string{} // server name -> first source (shadowing)

	for _, cfg := range cfgs {
		for _, perm := range cfg.Permissions {
			if isOverbroadPerm(perm) {
				out = append(out, Finding{
					CheckID: "AUDIT-MCP-PERM", Severity: "HIGH", Title: "Overbroad agent permission",
					Server: cfg.Source, Detail: perm,
					Fix: "Replace the wildcard with a minimal allowlist; avoid bypass modes.",
				})
			}
		}
		for _, s := range cfg.Servers {
			out = append(out, checkServer(s)...)
			if prev, ok := seenName[s.Name]; ok {
				out = append(out, Finding{
					CheckID: "AUDIT-MCP-SHADOW", Severity: "MEDIUM", Title: "Duplicate/shadowed MCP server name",
					Server: s.Name, Detail: "also defined in " + prev,
					Fix: "Rename one server; shadowed tool names are an injection risk.",
				})
			} else {
				seenName[s.Name] = s.Source
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return sevRank(out[i].Severity) > sevRank(out[j].Severity)
		}
		return out[i].CheckID < out[j].CheckID
	})
	return out
}

func checkServer(s Server) []Finding {
	var out []Finding
	full := strings.TrimSpace(s.Command + " " + strings.Join(s.Args, " "))

	// Unpinned npx/uvx server.
	if (strings.Contains(full, "npx") || strings.Contains(full, "uvx")) && !reVersioned.MatchString(full) {
		out = append(out, Finding{
			CheckID: "AUDIT-MCP-UNPINNED", Severity: "MEDIUM", Title: "Unpinned MCP server",
			Server: s.Name, Detail: full,
			Fix: "Pin to an exact version (e.g. pkg@1.2.3) so the fetched code can't change.",
		})
	}
	// Plaintext provider token in env.
	for k, v := range s.Env {
		if rePlaceholder.MatchString(strings.TrimSpace(v)) {
			continue
		}
		if reProviderKey.MatchString(v) {
			out = append(out, Finding{
				CheckID: "AUDIT-MCP-TOKEN", Severity: "HIGH", Title: "Plaintext token in MCP config",
				Server: s.Name, Detail: k + "=" + redact.Mask(v),
				Fix: "Reference an env var or OS keychain instead of embedding the secret.",
			})
		}
	}
	// Remote server over plain http.
	if strings.HasPrefix(strings.ToLower(s.URL), "http://") && !isLoopback(s.URL) {
		out = append(out, Finding{
			CheckID: "AUDIT-MCP-HTTP", Severity: "HIGH", Title: "Remote MCP server over http://",
			Server: s.Name, Detail: s.URL,
			Fix: "Use https:// for remote servers; tokens and traffic are otherwise in the clear.",
		})
	}
	return out
}

func isOverbroadPerm(p string) bool {
	lp := strings.ToLower(p)
	switch {
	case strings.Contains(lp, "bash(*)"), strings.Contains(lp, "write(*)"):
		return true
	case strings.Contains(lp, "dangerously-skip-permissions"), strings.Contains(lp, "bypasspermissions"):
		return true
	case strings.HasSuffix(lp, "(*)"):
		return true
	}
	return false
}

func isLoopback(url string) bool {
	l := strings.ToLower(url)
	return strings.Contains(l, "localhost") || strings.Contains(l, "127.0.0.1") || strings.Contains(l, "[::1]")
}

func sevRank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	}
	return 0
}

// Grade returns an A–F grade from the findings (worst severity dominates).
func Grade(fs []Finding) string {
	var crit, high, med int
	for _, f := range fs {
		switch strings.ToUpper(f.Severity) {
		case "CRITICAL":
			crit++
		case "HIGH":
			high++
		case "MEDIUM":
			med++
		}
	}
	switch {
	case crit > 0:
		return "F"
	case high > 1:
		return "D"
	case high == 1:
		return "C"
	case med > 0:
		return "B"
	default:
		return "A"
	}
}
