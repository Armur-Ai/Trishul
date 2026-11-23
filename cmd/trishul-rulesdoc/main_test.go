package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunGeneratesDocs(t *testing.T) {
	rulesDir := t.TempDir()
	outDir := t.TempDir()

	rule1 := `rules:
  - id: TEST-001
    title: First test rule
    short: A short summary of the first rule.
    description: |
      A longer description of the first rule.
    default_severity: HIGH
    default_confidence: 0.8
    maturity: stable
    languages: [go]
    file_kinds: [source]
    cwe: [CWE-123]
    owasp: [A01]
    references:
      - https://example.com/ref1
    fix: Do the safe thing instead.
    examples:
      bad: |
        dangerous()
      good: |
        safe()
    mode_default: block
`
	rule2 := `id: TEST-002
title: Second test rule
short: A short summary of the second rule.
description: A one-line description.
default_severity: LOW
default_confidence: 0.5
maturity: beta
mode_default: comment
`
	if err := os.WriteFile(filepath.Join(rulesDir, "one.yaml"), []byte(rule1), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "two.yaml"), []byte(rule2), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := run([]string{"--rules", rulesDir, "--out", outDir}); err != nil {
		t.Fatalf("run: %v", err)
	}

	// Per-rule files exist and carry their id + title.
	for _, tc := range []struct{ id, title string }{
		{"TEST-001", "First test rule"},
		{"TEST-002", "Second test rule"},
	} {
		path := filepath.Join(outDir, tc.id+".md")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		body := string(data)
		if !strings.Contains(body, tc.id) {
			t.Errorf("%s: missing id %q", path, tc.id)
		}
		if !strings.Contains(body, tc.title) {
			t.Errorf("%s: missing title %q", path, tc.title)
		}
	}

	// Example fences are emitted for the rule that has them.
	r1, err := os.ReadFile(filepath.Join(outDir, "TEST-001.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"```bad", "```good", "https://example.com/ref1", "## Fix"} {
		if !strings.Contains(string(r1), want) {
			t.Errorf("TEST-001.md missing %q", want)
		}
	}

	// README index exists and links both rules.
	readme, err := os.ReadFile(filepath.Join(outDir, "README.md"))
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	rbody := string(readme)
	for _, want := range []string{"[TEST-001](TEST-001.md)", "[TEST-002](TEST-002.md)", "First test rule", "2 rules"} {
		if !strings.Contains(rbody, want) {
			t.Errorf("README.md missing %q", want)
		}
	}
}

func TestRunErrorsOnBadRule(t *testing.T) {
	rulesDir := t.TempDir()
	outDir := t.TempDir()
	// Invalid: empty title + bad severity should fail validation.
	bad := `id: BAD-001
default_severity: NOPE
default_confidence: 0.5
maturity: stable
`
	if err := os.WriteFile(filepath.Join(rulesDir, "bad.yaml"), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--rules", rulesDir, "--out", outDir}); err == nil {
		t.Fatal("expected validation error, got nil")
	}
}
