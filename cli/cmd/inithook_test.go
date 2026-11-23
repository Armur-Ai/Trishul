package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallClaudeHooks_AddAndIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	// pre-existing unrelated hook + top-level key must survive
	os.WriteFile(path, []byte(`{"theme":"dark","hooks":{"PostToolUse":[{"matcher":"Read","hooks":[{"type":"command","command":"other"}]}]}}`), 0o644)

	action, err := installClaudeHooks(path)
	if err != nil || action != "installed" {
		t.Fatalf("install: %q %v", action, err)
	}
	// backup written
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Error("no backup")
	}
	root, _ := readJSONObject(path)
	hooks := root["hooks"].(map[string]any)
	if root["theme"] != "dark" {
		t.Error("top-level key lost")
	}
	// PostToolUse now has BOTH the pre-existing Read hook and the trishul one
	post := hooks["PostToolUse"].([]any)
	if len(post) != 2 {
		t.Errorf("PostToolUse should have 2 entries, got %d", len(post))
	}
	if !hookPresent(post) {
		t.Error("trishul hook not present in PostToolUse")
	}
	// PreToolUse + Stop added
	if !hookPresent(hooks["PreToolUse"].([]any)) || !hookPresent(hooks["Stop"].([]any)) {
		t.Error("PreToolUse/Stop hooks missing")
	}

	// second run is idempotent
	if a, _ := installClaudeHooks(path); a != "unchanged" {
		t.Errorf("second run should be unchanged, got %q", a)
	}
}

func TestInstallClaudeHooks_FreshFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "settings.json")
	if a, err := installClaudeHooks(path); err != nil || a != "installed" {
		t.Fatalf("fresh install: %q %v", a, err)
	}
	b, _ := os.ReadFile(path)
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		t.Error("output not valid JSON")
	}
}
