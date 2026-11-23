package mcpaudit

import (
	"strings"
	"testing"
)

func TestParseMCPJSON(t *testing.T) {
	data := []byte(`{
      "mcpServers": {
        "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]},
        "remote": {"url": "http://evil.example/mcp"}
      },
      "permissions": {"allow": ["Bash(*)"], "defaultMode": "bypassPermissions"}
    }`)
	cfg, err := ParseMCPJSON("claude_desktop_config.json", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Servers) != 2 {
		t.Fatalf("servers=%d", len(cfg.Servers))
	}
	if len(cfg.Permissions) != 2 {
		t.Errorf("perms=%v", cfg.Permissions)
	}
}

func TestCheck_UnpinnedTokenPermHTTP(t *testing.T) {
	cfg := Config{
		Source: "cfg.json",
		Servers: []Server{
			{Name: "fs", Command: "npx", Args: []string{"-y", "server-fs"}},                                              // unpinned
			{Name: "gh", Command: "server-gh", Env: map[string]string{"GITHUB_TOKEN": "ghp_" + strings.Repeat("a", 36)}}, // token
			{Name: "remote", URL: "http://api.example.com/mcp"},                                                          // http
		},
		Permissions: []string{"Bash(*)"}, // overbroad
	}
	fs := Check([]Config{cfg})
	got := map[string]bool{}
	for _, f := range fs {
		got[f.CheckID] = true
	}
	for _, want := range []string{"AUDIT-MCP-UNPINNED", "AUDIT-MCP-TOKEN", "AUDIT-MCP-HTTP", "AUDIT-MCP-PERM"} {
		if !got[want] {
			t.Errorf("missing check %s (got %v)", want, got)
		}
	}
	// token must be redacted in the detail
	for _, f := range fs {
		if f.CheckID == "AUDIT-MCP-TOKEN" && strings.Contains(f.Detail, strings.Repeat("a", 36)) {
			t.Error("token not redacted")
		}
	}
}

func TestCheck_PinnedAndPlaceholderClean(t *testing.T) {
	cfg := Config{Source: "c", Servers: []Server{
		{Name: "fs", Command: "npx", Args: []string{"-y", "server-fs@1.2.3"}},   // pinned
		{Name: "gh", Env: map[string]string{"TOKEN": "${GITHUB_TOKEN}"}},        // env ref
		{Name: "ai", Env: map[string]string{"OPENAI_API_KEY": "YOUR_KEY_HERE"}}, // placeholder
		{Name: "local", URL: "http://localhost:3000/mcp"},                       // loopback
	}}
	if fs := Check([]Config{cfg}); len(fs) != 0 {
		t.Errorf("clean config should have no findings, got %+v", fs)
	}
}

func TestCheck_ShadowedNames(t *testing.T) {
	a := Config{Source: "a.json", Servers: []Server{{Name: "fs", Source: "a.json", Command: "x@1"}}}
	b := Config{Source: "b.json", Servers: []Server{{Name: "fs", Source: "b.json", Command: "y@1"}}}
	fs := Check([]Config{a, b})
	found := false
	for _, f := range fs {
		if f.CheckID == "AUDIT-MCP-SHADOW" {
			found = true
		}
	}
	if !found {
		t.Errorf("duplicate server name not flagged: %+v", fs)
	}
}

func TestGrade(t *testing.T) {
	if Grade(nil) != "A" {
		t.Error("clean => A")
	}
	if Grade([]Finding{{Severity: "CRITICAL"}}) != "F" {
		t.Error("critical => F")
	}
	if Grade([]Finding{{Severity: "HIGH"}}) != "C" {
		t.Error("one high => C")
	}
	if Grade([]Finding{{Severity: "MEDIUM"}}) != "B" {
		t.Error("medium => B")
	}
}
