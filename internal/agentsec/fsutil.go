package agentsec

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "dist": true, "build": true,
	".next": true, "vendor": true, "target": true, ".venv": true,
}

// WalkFiles invokes fn for each regular file under dir (read-only) whose base
// name + path satisfy match. Noise directories and files larger than 2 MiB are
// skipped. Analyzers should use this rather than redefining their own walk.
func WalkFiles(dir string, match func(name, path string) bool, fn func(path string, content []byte)) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !match(d.Name(), path) {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > 2<<20 {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		fn(path, b)
		return nil
	})
}

// Rel returns path relative to dir (falls back to the original path).
func Rel(dir, path string) string {
	if r, err := filepath.Rel(dir, path); err == nil {
		return r
	}
	return path
}

// SplitLines splits content into lines for line-number reporting.
func SplitLines(content []byte) []string { return strings.Split(string(content), "\n") }
