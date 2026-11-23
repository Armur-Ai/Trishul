package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunAuditMCP_Table(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, ".mcp.json")
	os.WriteFile(cfg, []byte(`{"mcpServers":{"fs":{"command":"npx","args":["-y","server-fs"]}}}`), 0o644)

	var b strings.Builder
	code, err := runAuditMCP("", cfg, "table", "", "", &b)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 { // no fail-on set
		t.Errorf("exit code=%d want 0", code)
	}
	if !strings.Contains(b.String(), "AUDIT-MCP-UNPINNED") || !strings.Contains(b.String(), "grade") {
		t.Errorf("table output missing content:\n%s", b.String())
	}
}

func TestRunAuditMCP_JSONAndFailOn(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, ".mcp.json")
	// a remote http server -> HIGH finding
	os.WriteFile(cfg, []byte(`{"mcpServers":{"r":{"url":"http://evil.example/mcp"}}}`), 0o644)

	var b strings.Builder
	code, err := runAuditMCP("", cfg, "json", "", "high", &b)
	if err != nil {
		t.Fatal(err)
	}
	if code != 2 {
		t.Errorf("fail-on high should exit 2 for a HIGH finding, got %d", code)
	}
	if !strings.Contains(b.String(), "AUDIT-MCP-HTTP") {
		t.Errorf("json output missing finding:\n%s", b.String())
	}
}

func TestRunAuditMCP_ShareCard(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, ".mcp.json")
	os.WriteFile(cfg, []byte(`{"mcpServers":{"r":{"url":"http://evil.example/mcp"}}}`), 0o644)
	share := filepath.Join(dir, "card.svg")

	var b strings.Builder
	if _, err := runAuditMCP("", cfg, "table", share, "", &b); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(share)
	if err != nil || !strings.HasPrefix(string(data), "<svg") {
		t.Fatalf("share card not written as svg: %v", err)
	}
	// card must not leak the config path
	if strings.Contains(string(data), dir) {
		t.Error("share card leaked a path")
	}
}
