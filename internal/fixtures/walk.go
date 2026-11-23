// Package fixtures provides a reusable harness for real-world false-positive /
// true-positive regression tests (plan P0.2). Each analyzer keeps minimal
// sanitized cases under testdata/fp/<rule>/<case>/ (must produce 0 findings) and
// testdata/tp/<rule>/<case>/ (must produce >= 1), and a one-line table-driven
// test walks them with Walk. This locks in precision fixes: an FP fixture is red
// until the fix lands, then stays green.
package fixtures

import (
	"os"
	"path/filepath"
)

// TestingT is the subset of *testing.T the harness needs, so Walk itself is
// testable with a fake.
type TestingT interface {
	Helper()
	Errorf(format string, args ...interface{})
}

// ScanFunc runs an analyzer over a case directory and returns the number of
// findings it produced.
type ScanFunc func(dir string) (int, error)

// Walk runs scan over every case directory under root/fp and root/tp. A case
// directory is any directory that directly contains at least one regular file;
// this allows the testdata/fp/<rule>/<case>/ nesting without hard-coding depth.
// FP cases must yield 0 findings; TP cases must yield >= 1. Missing fp or tp
// trees are simply skipped (not every analyzer has both yet).
func Walk(t TestingT, root string, scan ScanFunc) {
	t.Helper()
	walkClass(t, filepath.Join(root, "fp"), scan, false)
	walkClass(t, filepath.Join(root, "tp"), scan, true)
}

func walkClass(t TestingT, base string, scan ScanFunc, wantFindings bool) {
	cases, err := caseDirs(base)
	if err != nil || len(cases) == 0 {
		return
	}
	for _, dir := range cases {
		n, err := scan(dir)
		if err != nil {
			t.Errorf("%s: scan error: %v", dir, err)
			continue
		}
		if wantFindings && n < 1 {
			t.Errorf("TP fixture %s: expected >=1 finding, got 0", dir)
		}
		if !wantFindings && n != 0 {
			t.Errorf("FP fixture %s: expected 0 findings, got %d", dir, n)
		}
	}
}

// caseDirs returns every directory under base that directly contains a regular
// file (a "leaf" case directory).
func caseDirs(base string) ([]string, error) {
	if _, err := os.Stat(base); err != nil {
		return nil, err
	}
	var out []string
	err := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() {
			return err
		}
		entries, derr := os.ReadDir(path)
		if derr != nil {
			return derr
		}
		for _, e := range entries {
			if !e.IsDir() {
				out = append(out, path)
				break
			}
		}
		return nil
	})
	return out, err
}
