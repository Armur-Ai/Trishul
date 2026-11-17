package engine

import (
	"os"
	"path/filepath"
	"testing"
)

// ScanLocal must run in-process and leave the target untouched, even when the
// external tools are not installed (they are reported as skipped, not fatal).
func TestScanLocal_RunsAndIsReadOnly(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	content := []byte("package main\nfunc main() {}\n")
	if err := os.WriteFile(src, content, 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := ScanLocal(dir, "go")
	if err != nil {
		t.Fatalf("ScanLocal returned error: %v", err)
	}
	if res == nil {
		t.Fatal("expected a non-nil result")
	}

	// The source file must be byte-identical afterwards (read-only guarantee).
	got, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("source file missing after scan: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("scan modified the target file")
	}
}
