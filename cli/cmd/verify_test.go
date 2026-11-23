package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRunVerify_EmitsClaim(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	if err := runVerify(dir, "acme/app", "abc123", "refs/heads/main", &b); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(b.String()), &m); err != nil {
		t.Fatalf("claim not valid JSON: %v\n%s", err, b.String())
	}
	if m["repo"] != "acme/app" || m["commit_sha"] != "abc123" {
		t.Errorf("claim fields wrong: %v", m)
	}
	if m["predicate_type"] == nil {
		t.Error("missing predicate_type")
	}
	// never leaks code/paths
	for _, forbidden := range []string{"snippet", "source", "path"} {
		if _, ok := m[forbidden]; ok {
			t.Errorf("claim must not contain %q", forbidden)
		}
	}
}

func TestFirstNonEmptyStr(t *testing.T) {
	if firstNonEmptyStr("", "", "x") != "x" {
		t.Error("should pick first non-empty")
	}
	if firstNonEmptyStr("", "") != "" {
		t.Error("all-empty should be empty")
	}
}
