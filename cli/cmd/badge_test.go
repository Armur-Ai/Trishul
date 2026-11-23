package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunBadge_PrintsAndWrites(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, ".trishul", "badge.json")
	var b strings.Builder
	if err := runBadge(dir, out, &b); err != nil {
		t.Fatal(err)
	}
	// stdout has valid shields JSON
	line := strings.SplitN(b.String(), "\n", 2)[0]
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("badge JSON invalid: %v (%q)", err, line)
	}
	if m["schemaVersion"].(float64) != 1 || m["label"] != "trishul" {
		t.Errorf("badge fields wrong: %v", m)
	}
	// file written
	data, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(data), "schemaVersion") {
		t.Fatalf("badge file not written: %v", err)
	}
	if !strings.Contains(b.String(), "img.shields.io/endpoint") {
		t.Errorf("markdown snippet missing:\n%s", b.String())
	}
}
