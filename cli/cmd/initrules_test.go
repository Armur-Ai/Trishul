package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	trishul "github.com/Armur-Ai/Trishul"
	"github.com/Armur-Ai/Trishul/internal/agentrules"
)

func TestParseTools(t *testing.T) {
	if d := parseTools(""); len(d) != 3 {
		t.Errorf("default tools=%v", d)
	}
	got := parseTools("claude, copilot ,windsurf")
	if len(got) != 3 || got[1] != agentrules.Copilot {
		t.Errorf("parsed=%v", got)
	}
}

func TestRunInitRules_CreatesAndIdempotent(t *testing.T) {
	cat, err := trishul.Catalog()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	// make it look like a supabase project so stack detection fires
	os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"dependencies":{"@supabase/supabase-js":"2"}}`), 0o644)

	var b strings.Builder
	if err := runInitRules(root, []agentrules.Tool{agentrules.Claude}, cat, &b); err != nil {
		t.Fatal(err)
	}
	claude := filepath.Join(root, "CLAUDE.md")
	data, err := os.ReadFile(claude)
	if err != nil {
		t.Fatalf("CLAUDE.md not written: %v", err)
	}
	if !strings.Contains(string(data), agentrules.MarkerBegin) || !strings.Contains(string(data), "managed by Trishul") {
		t.Errorf("CLAUDE.md missing managed section:\n%s", data)
	}
	if !strings.Contains(b.String(), "created: CLAUDE.md") {
		t.Errorf("expected created message, got %q", b.String())
	}

	// second run is idempotent (unchanged)
	var b2 strings.Builder
	if err := runInitRules(root, []agentrules.Tool{agentrules.Claude}, cat, &b2); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b2.String(), "unchanged: CLAUDE.md") {
		t.Errorf("second run should be unchanged, got %q", b2.String())
	}
	data2, _ := os.ReadFile(claude)
	if string(data2) != string(data) {
		t.Error("idempotent run changed the file")
	}
}

func TestRunInitRules_PreservesSurroundingContent(t *testing.T) {
	cat, _ := trishul.Catalog()
	root := t.TempDir()
	claude := filepath.Join(root, "CLAUDE.md")
	os.WriteFile(claude, []byte("# My project\n\nMy own notes.\n"), 0o644)

	var b strings.Builder
	if err := runInitRules(root, []agentrules.Tool{agentrules.Claude}, cat, &b); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(claude)
	if !strings.Contains(string(data), "My own notes.") || !strings.Contains(string(data), agentrules.MarkerBegin) {
		t.Errorf("should preserve user content + add section:\n%s", data)
	}
}
