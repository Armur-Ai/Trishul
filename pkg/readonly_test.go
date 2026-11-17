package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// treeHash returns a map of relative-path -> content hash for every file under
// root, so two snapshots can be compared for byte-identity.
func treeHash(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		sum := sha256.Sum256(b)
		out[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

func writeFixture(t *testing.T, dir string) {
	t.Helper()
	files := map[string]string{
		"main.go":       "package main\nfunc main() {}\n",
		"package.json":  `{"name":"x"}`,
		".env":          "SECRET=do-not-touch\n",
		"Dockerfile":    "FROM scratch\n",
		"sub/notes.txt": "important user notes\n",
	}
	for rel, content := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestReadOnlyInvariant_UserTargetUntouched is the core safety contract: a scan
// target that is NOT one of Trishul's managed working copies must be left
// byte-identical even by the historically-destructive pruning function.
func TestReadOnlyInvariant_UserTargetUntouched(t *testing.T) {
	// A directory under the repo working tree is deliberately NOT a managed root
	// (managed roots are the repos dir and the system temp dir).
	dir, err := os.MkdirTemp(".", "readonly_user_target_")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	writeFixture(t, dir)
	if IsManagedPath(dir) {
		t.Skipf("fixture dir %q is unexpectedly managed in this environment; invariant covered elsewhere", dir)
	}

	before := treeHash(t, dir)
	// Even asking it to keep only Go files must not delete package.json/.env/etc.
	if err := RemoveNonRelevantFiles(dir, "go"); err != nil {
		t.Fatalf("RemoveNonRelevantFiles returned error: %v", err)
	}
	after := treeHash(t, dir)

	if len(before) != len(after) {
		t.Fatalf("file count changed: before=%d after=%d (user files were deleted!)", len(before), len(after))
	}
	for rel, h := range before {
		if after[rel] != h {
			t.Errorf("file %q changed or was removed — scan target must be read-only", rel)
		}
	}
}

// TestPruning_WorksInsideManagedCopy confirms the pruning behaviour is retained
// where it is safe: inside a managed working copy (system temp).
func TestPruning_WorksInsideManagedCopy(t *testing.T) {
	dir := t.TempDir() // under os.TempDir() -> managed
	writeFixture(t, dir)
	if !IsManagedPath(dir) {
		t.Skipf("temp dir %q unexpectedly not managed here", dir)
	}
	if err := RemoveNonRelevantFiles(dir, "go"); err != nil {
		t.Fatalf("RemoveNonRelevantFiles: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "main.go")); err != nil {
		t.Errorf("expected main.go to be kept in managed copy: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "package.json")); !os.IsNotExist(err) {
		t.Errorf("expected package.json to be pruned in managed copy")
	}
}
