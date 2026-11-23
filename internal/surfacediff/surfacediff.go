// Package surfacediff summarizes how a PR changes the repo's "AI agent surface"
// (plan P4.4): the MCP servers it wires, the instruction files an agent reads,
// the permissions it grants, and the install hooks it runs. In PR mode this is
// rendered as a "your AI agent's environment changed" table even when there are
// no findings — the Socket-style informational callout.
package surfacediff

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Surface is the set of agent-surface facts extracted from a tree.
type Surface struct {
	MCPServers       map[string]string // name -> command (+ pinned version if present)
	InstructionFiles []string          // CLAUDE.md, AGENTS.md, .cursorrules, ...
	Permissions      []string          // allow-list entries from agent settings
	InstallHooks     []string          // hook commands from agent settings
}

func newSurface() Surface {
	return Surface{MCPServers: map[string]string{}}
}

// instructionNames are the agent-instruction files an agent reads.
var instructionNames = map[string]bool{
	"CLAUDE.md": true, "AGENTS.md": true, ".cursorrules": true, ".windsurfrules": true,
}

// Extract scans a tree for agent-surface facts. It only reads files (never
// executes anything) and ignores unreadable/oversized entries.
func Extract(root string) Surface {
	s := newSurface()
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		base := filepath.Base(path)
		switch {
		case instructionNames[base]:
			s.InstructionFiles = append(s.InstructionFiles, rel)
		case base == "mcp.json" || base == ".mcp.json":
			mergeMCP(&s, path)
		case base == "settings.json" && strings.Contains(rel, ".claude"):
			mergeSettings(&s, path)
		}
		return nil
	})
	sort.Strings(s.InstructionFiles)
	sort.Strings(s.Permissions)
	sort.Strings(s.InstallHooks)
	return s
}

func mergeMCP(s *Surface, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var cfg struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	if json.Unmarshal(data, &cfg) != nil {
		return
	}
	for name, srv := range cfg.MCPServers {
		cmd := strings.TrimSpace(srv.Command + " " + strings.Join(srv.Args, " "))
		s.MCPServers[name] = cmd
	}
}

func mergeSettings(s *Surface, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var cfg struct {
		Permissions struct {
			Allow []string `json:"allow"`
		} `json:"permissions"`
		Hooks map[string]interface{} `json:"hooks"`
	}
	if json.Unmarshal(data, &cfg) != nil {
		return
	}
	s.Permissions = append(s.Permissions, cfg.Permissions.Allow...)
	for event := range cfg.Hooks {
		s.InstallHooks = append(s.InstallHooks, event)
	}
}

// Report is the diff of two surfaces.
type Report struct {
	AddedServers   map[string]string
	RemovedServers []string
	AddedFiles     []string
	RemovedFiles   []string
	AddedPerms     []string
	RemovedPerms   []string
	AddedHooks     []string
}

// Empty reports whether nothing changed.
func (r Report) Empty() bool {
	return len(r.AddedServers) == 0 && len(r.RemovedServers) == 0 &&
		len(r.AddedFiles) == 0 && len(r.RemovedFiles) == 0 &&
		len(r.AddedPerms) == 0 && len(r.RemovedPerms) == 0 && len(r.AddedHooks) == 0
}

// Diff compares base→head surfaces.
func Diff(base, head Surface) Report {
	r := Report{AddedServers: map[string]string{}}
	for name, cmd := range head.MCPServers {
		if _, ok := base.MCPServers[name]; !ok {
			r.AddedServers[name] = cmd
		}
	}
	for name := range base.MCPServers {
		if _, ok := head.MCPServers[name]; !ok {
			r.RemovedServers = append(r.RemovedServers, name)
		}
	}
	r.AddedFiles = sub(head.InstructionFiles, base.InstructionFiles)
	r.RemovedFiles = sub(base.InstructionFiles, head.InstructionFiles)
	r.AddedPerms = sub(head.Permissions, base.Permissions)
	r.RemovedPerms = sub(base.Permissions, head.Permissions)
	r.AddedHooks = sub(head.InstallHooks, base.InstallHooks)
	sort.Strings(r.RemovedServers)
	return r
}

// sub returns elements of a not present in b, sorted and de-duplicated.
func sub(a, b []string) []string {
	set := map[string]bool{}
	for _, x := range b {
		set[x] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, x := range a {
		if !set[x] && !seen[x] {
			out = append(out, x)
			seen[x] = true
		}
	}
	sort.Strings(out)
	return out
}

// Markdown renders the "agent environment changed" callout, or "" when empty.
func (r Report) Markdown() string {
	if r.Empty() {
		return ""
	}
	var b strings.Builder
	b.WriteString("### 🤖 Your AI agent's environment changed\n\n")
	servers := make([]string, 0, len(r.AddedServers))
	for name := range r.AddedServers {
		servers = append(servers, name)
	}
	sort.Strings(servers)
	for _, name := range servers {
		fmt.Fprintf(&b, "- **+ MCP server** `%s` → `%s`\n", name, r.AddedServers[name])
	}
	for _, name := range r.RemovedServers {
		fmt.Fprintf(&b, "- **− MCP server** `%s`\n", name)
	}
	for _, f := range r.AddedFiles {
		fmt.Fprintf(&b, "- **+ instruction file** `%s`\n", f)
	}
	for _, p := range r.AddedPerms {
		fmt.Fprintf(&b, "- **+ permission** `%s`\n", p)
	}
	for _, h := range r.AddedHooks {
		fmt.Fprintf(&b, "- **+ install hook** `%s`\n", h)
	}
	return b.String()
}
