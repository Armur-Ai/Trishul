package agentsec

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWalkFiles_SkipsNoiseAndReads(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "node_modules"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "node_modules", "x.md"), []byte("ignored"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "CLAUDE.md"), []byte("line1\nline2"), 0o644)

	var seen []string
	_ = WalkFiles(dir, func(name, _ string) bool { return name == "CLAUDE.md" }, func(p string, c []byte) {
		seen = append(seen, Rel(dir, p))
		if len(SplitLines(c)) != 2 {
			t.Errorf("expected 2 lines, got %d", len(SplitLines(c)))
		}
	})
	if len(seen) != 1 || seen[0] != "CLAUDE.md" {
		t.Errorf("WalkFiles should read CLAUDE.md and skip node_modules; got %v", seen)
	}
}
