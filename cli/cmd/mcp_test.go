package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestUpsertMCPServer_AddUpdateUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	// pre-existing other server must be preserved
	os.WriteFile(path, []byte(`{"mcpServers":{"other":{"command":"x"}},"theme":"dark"}`), 0o644)

	entry := map[string]any{"command": "trishul", "args": []string{"mcp"}}
	action, err := upsertMCPServer(path, "trishul", entry)
	if err != nil || action != "added" {
		t.Fatalf("add: %q %v", action, err)
	}
	// backup written
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Error("no backup written")
	}
	// other server + top-level key preserved
	root, _ := readJSONObject(path)
	servers := root["mcpServers"].(map[string]any)
	if _, ok := servers["other"]; !ok {
		t.Error("existing server lost")
	}
	if root["theme"] != "dark" {
		t.Error("top-level key lost")
	}
	// second run unchanged
	if a, _ := upsertMCPServer(path, "trishul", entry); a != "unchanged" {
		t.Errorf("idempotent run should be unchanged, got %q", a)
	}
	// changed entry -> updated
	if a, _ := upsertMCPServer(path, "trishul", map[string]any{"command": "trishul", "args": []string{"mcp", "--http"}}); a != "updated" {
		t.Errorf("changed entry should be updated, got %q", a)
	}
}

func TestRemoveMCPServer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	os.WriteFile(path, []byte(`{"mcpServers":{"trishul":{"command":"trishul"},"other":{"command":"x"}}}`), 0o644)
	if a, err := removeMCPServer(path, "trishul"); err != nil || a != "removed" {
		t.Fatalf("remove: %q %v", a, err)
	}
	root, _ := readJSONObject(path)
	servers := root["mcpServers"].(map[string]any)
	if _, ok := servers["trishul"]; ok {
		t.Error("trishul not removed")
	}
	if _, ok := servers["other"]; !ok {
		t.Error("other server wrongly removed")
	}
	// removing again -> not present
	if a, _ := removeMCPServer(path, "trishul"); a != "not present" {
		t.Errorf("second remove should be 'not present', got %q", a)
	}
}

func TestMCPClientConfigPath(t *testing.T) {
	home := "/home/u"
	cases := map[string]string{
		"claude":   filepath.Join(home, ".claude.json"),
		"cursor":   filepath.Join(home, ".cursor", "mcp.json"),
		"windsurf": filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"),
	}
	for client, want := range cases {
		got, err := mcpClientConfigPath(client, false, home)
		if err != nil || got != want {
			t.Errorf("%s: got %q want %q (%v)", client, got, want, err)
		}
	}
	if p, _ := mcpClientConfigPath("cursor", true, home); p != filepath.Join(".cursor", "mcp.json") {
		t.Errorf("project cursor path=%q", p)
	}
	if _, err := mcpClientConfigPath("bogus", false, home); err == nil {
		t.Error("unknown client should error")
	}
}

func TestWriteJSONObject_ValidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.json")
	if err := writeJSONObject(path, map[string]any{"a": 1}); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	b, _ := os.ReadFile(path)
	if json.Unmarshal(b, &m) != nil {
		t.Error("output not valid JSON")
	}
}
