package fixtures

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeT records Errorf calls so we can assert the harness's pass/fail decisions.
type fakeT struct{ errs []string }

func (f *fakeT) Helper() {}
func (f *fakeT) Errorf(format string, args ...interface{}) {
	f.errs = append(f.errs, format)
}

func writeCase(t *testing.T, dir, name, content string) {
	t.Helper()
	d := filepath.Join(dir, name)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "case.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestWalk_PassesWhenCountsMatch(t *testing.T) {
	root := t.TempDir()
	writeCase(t, filepath.Join(root, "fp", "RULE"), "clean", "safe")
	writeCase(t, filepath.Join(root, "tp", "RULE"), "vuln", "bad")

	// scan: "bad" files yield 1 finding, others 0 — matches fp/tp expectations.
	scan := func(dir string) (int, error) {
		b, _ := os.ReadFile(filepath.Join(dir, "case.txt"))
		if strings.Contains(string(b), "bad") {
			return 1, nil
		}
		return 0, nil
	}
	ft := &fakeT{}
	Walk(ft, root, scan)
	if len(ft.errs) != 0 {
		t.Errorf("expected no errors, got %v", ft.errs)
	}
}

func TestWalk_FailsOnFalsePositive(t *testing.T) {
	root := t.TempDir()
	writeCase(t, filepath.Join(root, "fp", "RULE"), "clean", "safe")
	scan := func(string) (int, error) { return 1, nil } // wrongly fires on the FP case
	ft := &fakeT{}
	Walk(ft, root, scan)
	if len(ft.errs) != 1 {
		t.Errorf("expected 1 FP failure, got %d", len(ft.errs))
	}
}

func TestWalk_FailsWhenTPMisses(t *testing.T) {
	root := t.TempDir()
	writeCase(t, filepath.Join(root, "tp", "RULE"), "vuln", "bad")
	scan := func(string) (int, error) { return 0, nil } // fails to fire on the TP case
	ft := &fakeT{}
	Walk(ft, root, scan)
	if len(ft.errs) != 1 {
		t.Errorf("expected 1 TP failure, got %d", len(ft.errs))
	}
}

func TestWalk_MissingTreesSkipped(t *testing.T) {
	ft := &fakeT{}
	Walk(ft, t.TempDir(), func(string) (int, error) { return 0, nil })
	if len(ft.errs) != 0 {
		t.Errorf("missing fp/tp trees should be skipped, got %v", ft.errs)
	}
}
