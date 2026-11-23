package agentrules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Armur-Ai/Trishul/internal/rules"
)

func loadCat(t *testing.T) *rules.Catalog {
	t.Helper()
	c, err := rules.LoadCatalog("../../rules")
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	return c
}

func TestFileFor(t *testing.T) {
	if FileFor(Claude) != "CLAUDE.md" || FileFor(Cursor) != ".cursor/rules/trishul-security.mdc" {
		t.Error("file paths wrong")
	}
	if FileFor("bogus") != "" {
		t.Error("unknown tool should be empty")
	}
}

func TestStacks(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"dependencies":{"next":"14","@supabase/supabase-js":"2","express":"4"}}`), 0o644)
	os.WriteFile(filepath.Join(root, "go.mod"), []byte("module x\n"), 0o644)
	got := Stacks(root)
	want := map[string]bool{"nextjs": true, "supabase": true, "express": true, "go": true}
	for _, s := range got {
		delete(want, s)
	}
	if len(want) != 0 {
		t.Errorf("stacks=%v, missing %v", got, want)
	}
}

func TestRender_StackAwareAndBounded(t *testing.T) {
	cat := loadCat(t)
	body := Render(cat, []string{"supabase"}, Claude)
	if !strings.Contains(body, "managed by Trishul") {
		t.Error("missing header")
	}
	if !strings.Contains(body, "supabase") {
		t.Error("should name the detected stack")
	}
	// supabase stack should surface an RLS rule
	if !strings.Contains(body, "SUPABASE") && !strings.Contains(strings.ToLower(body), "row level security") && !strings.Contains(strings.ToLower(body), "rls") {
		t.Errorf("supabase rules not included:\n%s", body)
	}
	if lines := strings.Count(body, "\n"); lines > 150 {
		t.Errorf("rendered body too long: %d lines", lines)
	}
}

func TestUpsertSection_InsertThenIdempotentReplace(t *testing.T) {
	body1 := "## Security rules (managed by Trishul)\n\n- rule A\n"
	out1 := UpsertSection("# My project\n\nSome docs.\n", body1)
	if !strings.Contains(out1, MarkerBegin) || !strings.Contains(out1, "rule A") || !strings.Contains(out1, "# My project") {
		t.Fatalf("insert wrong:\n%s", out1)
	}
	// re-running with the same body is idempotent
	out2 := UpsertSection(out1, body1)
	if out2 != out1 {
		t.Errorf("not idempotent:\n%q\n---\n%q", out1, out2)
	}
	// a new body replaces only between the markers, preserving surrounding text
	out3 := UpsertSection(out1, "## Security rules (managed by Trishul)\n\n- rule B\n")
	if strings.Contains(out3, "rule A") || !strings.Contains(out3, "rule B") || !strings.Contains(out3, "# My project") {
		t.Errorf("replace wrong:\n%s", out3)
	}
	if strings.Count(out3, MarkerBegin) != 1 {
		t.Error("marker duplicated")
	}
}
