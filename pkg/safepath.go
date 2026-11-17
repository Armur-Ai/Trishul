package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// managedRoots returns the directory roots under which Trishul is permitted to
// delete files: the repository/scan working area and the system temp dir. A
// scan must NEVER modify or delete files outside these roots — the scanned
// target is always treated as read-only.
func managedRoots() []string {
	return []string{reposBaseDir(), os.TempDir()}
}

// IsManagedPath reports whether path lies strictly inside one of Trishul's
// managed working roots. It resolves the path to an absolute, cleaned form and
// rejects the roots themselves, "/", and anything outside them. This is the
// single predicate that keeps destructive operations away from user source.
func IsManagedPath(path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	abs = filepath.Clean(abs)
	if abs == "/" || abs == "." {
		return false
	}
	for _, root := range managedRoots() {
		r, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		r = filepath.Clean(r)
		if r == "/" || r == "" {
			continue
		}
		// Must be strictly inside the root, never the root itself.
		if abs != r && strings.HasPrefix(abs, r+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

// SafeRemoveAll removes path only if it lies inside a managed working root.
// Outside those roots it refuses and returns an error, so a scan can never
// delete a user's source tree even if a caller passes the wrong path.
func SafeRemoveAll(path string) error {
	if !IsManagedPath(path) {
		return fmt.Errorf("refusing to delete %q: outside Trishul's managed working directories (read-only safety guard)", path)
	}
	return os.RemoveAll(path)
}
