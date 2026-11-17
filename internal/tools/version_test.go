package internal

import (
	"strings"
	"testing"
)

func TestToolVersion(t *testing.T) {
	if !ToolAvailable("go") {
		t.Skip("go not on PATH")
	}
	v, ok := ToolVersion("go")
	if !ok || !strings.Contains(strings.ToLower(v), "go") {
		t.Errorf("ToolVersion(go) = %q, %v", v, ok)
	}
	if _, ok := ToolVersion("this-tool-does-not-exist-xyzzy"); ok {
		t.Errorf("missing tool must report no version")
	}
}
