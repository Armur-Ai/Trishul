package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsManagedPath(t *testing.T) {
	tmp := t.TempDir() // inside os.TempDir(), a managed root
	inside := filepath.Join(tmp, "repo123")
	if !IsManagedPath(inside) {
		t.Errorf("expected %q to be managed (inside temp root)", inside)
	}
	// User source trees and system roots must never be managed.
	for _, p := range []string{"/", "/Users/someone/project", "/etc", "."} {
		if IsManagedPath(p) {
			t.Errorf("expected %q to NOT be managed", p)
		}
	}
	// The temp root itself is not managed (only paths strictly within it).
	if IsManagedPath(os.TempDir()) {
		t.Errorf("the temp root itself must not be managed")
	}
}

func TestSafeRemoveAll_RefusesOutsideManaged(t *testing.T) {
	// A path that looks like real user source must be refused, not deleted.
	if err := SafeRemoveAll("/Users/someone/important-project"); err == nil {
		t.Errorf("SafeRemoveAll must refuse a non-managed path")
	}
}

func TestSafeRemoveAll_RemovesManaged(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "work")
	if err := os.MkdirAll(filepath.Join(target, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := SafeRemoveAll(target); err != nil {
		t.Fatalf("SafeRemoveAll on managed path failed: %v", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("expected %q to be removed", target)
	}
}
