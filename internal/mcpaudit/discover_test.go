package mcpaudit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientConfigPaths_Includes(t *testing.T) {
	paths := ClientConfigPaths("/home/u")
	joined := strings.Join(paths, "\n")
	for _, want := range []string{".claude.json", filepath.Join(".cursor", "mcp.json"), filepath.Join(".claude", "settings.json")} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing candidate %s", want)
		}
	}
}

func TestDiscover_OnlyExisting(t *testing.T) {
	home := t.TempDir()
	// seed one real config
	os.MkdirAll(filepath.Join(home, ".cursor"), 0o755)
	os.WriteFile(filepath.Join(home, ".cursor", "mcp.json"), []byte(`{"mcpServers":{}}`), 0o644)
	got := Discover(home)
	if len(got) != 1 || !strings.HasSuffix(got[0], filepath.Join(".cursor", "mcp.json")) {
		t.Fatalf("discover=%v", got)
	}
}

func TestAuditHome_EndToEnd(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".cursor"), 0o755)
	os.WriteFile(filepath.Join(home, ".cursor", "mcp.json"),
		[]byte(`{"mcpServers":{"fs":{"command":"npx","args":["-y","server-fs"]}}}`), 0o644)
	findings, cfgs := AuditHome(home, "")
	if len(cfgs) != 1 {
		t.Fatalf("configs=%d", len(cfgs))
	}
	var unpinned bool
	for _, f := range findings {
		if f.CheckID == "AUDIT-MCP-UNPINNED" {
			unpinned = true
		}
	}
	if !unpinned {
		t.Errorf("expected unpinned finding, got %+v", findings)
	}
}

func TestAuditHome_ExplicitPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".mcp.json")
	os.WriteFile(p, []byte(`{"mcpServers":{"remote":{"url":"http://evil.example/mcp"}}}`), 0o644)
	findings, _ := AuditHome("", p)
	var http bool
	for _, f := range findings {
		if f.CheckID == "AUDIT-MCP-HTTP" {
			http = true
		}
	}
	if !http {
		t.Errorf("explicit-path audit missed http finding: %+v", findings)
	}
}
