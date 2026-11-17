package internal

import (
	"os"
	"path/filepath"
	"testing"

	utils "github.com/Armur-Ai/Trishul/pkg"
)

// depWriteFile writes a file under dir, creating parents as needed.
func depWriteFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

// depFindings extracts the vibe_security finding slice, asserting the category
// key is present.
func depFindings(t *testing.T, res map[string]interface{}) []interface{} {
	t.Helper()
	raw, ok := res[utils.VIBE_SECURITY]
	if !ok {
		t.Fatalf("result missing %q key; got keys %v", utils.VIBE_SECURITY, depKeysOf(res))
	}
	findings, ok := raw.([]interface{})
	if !ok {
		t.Fatalf("%q value is %T, want []interface{}", utils.VIBE_SECURITY, raw)
	}
	return findings
}

func depKeysOf(m map[string]interface{}) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// depCheckIDs returns the multiset of check_ids present in the findings and also
// asserts every finding has a well-formed int line and the required keys.
func depCheckIDs(t *testing.T, findings []interface{}) map[string]int {
	t.Helper()
	counts := map[string]int{}
	for i, f := range findings {
		m, ok := f.(map[string]interface{})
		if !ok {
			t.Fatalf("finding %d is %T, want map[string]interface{}", i, f)
		}
		line, ok := m["line"].(int)
		if !ok {
			t.Fatalf("finding %d line is %T, want int", i, m["line"])
		}
		if line < 1 {
			t.Fatalf("finding %d has non-positive line %d", i, line)
		}
		for _, k := range []string{"path", "message", "severity", "check_id", "cwe", "confidence", "remediation"} {
			if _, ok := m[k]; !ok {
				t.Fatalf("finding %d missing key %q", i, k)
			}
		}
		id, _ := m["check_id"].(string)
		counts[id]++
	}
	return counts
}

func TestDepProvenance_NonRegistrySource(t *testing.T) {
	dir := t.TempDir()
	depWriteFile(t, dir, "package.json", `{
  "name": "demo",
  "dependencies": {
    "foo": "github:evil/foo",
    "good": "^1.2.3"
  }
}`)
	// No lockfile -> "good" is a floating range and would be VIBE-DEP-002.
	res, err := RunDependencyProvenance(dir)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	findings := depFindings(t, res)
	counts := depCheckIDs(t, findings)
	if counts["VIBE-DEP-001"] != 1 {
		t.Fatalf("want 1 VIBE-DEP-001 for github: source, got %d (counts=%v)", counts["VIBE-DEP-001"], counts)
	}
	// Confirm the 001 finding points at the right dep line (line 4).
	for _, f := range findings {
		m := f.(map[string]interface{})
		if m["check_id"] == "VIBE-DEP-001" {
			if got := m["line"].(int); got != 4 {
				t.Fatalf("VIBE-DEP-001 line = %d, want 4", got)
			}
			if m["cwe"] != "CWE-1104" {
				t.Fatalf("VIBE-DEP-001 cwe = %v, want CWE-1104", m["cwe"])
			}
		}
	}
}

func TestDepProvenance_FloatingNoLockfile(t *testing.T) {
	dir := t.TempDir()
	depWriteFile(t, dir, "package.json", `{
  "dependencies": {
    "bar": "*"
  }
}`)
	res, err := RunDependencyProvenance(dir)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	counts := depCheckIDs(t, depFindings(t, res))
	if counts["VIBE-DEP-002"] != 1 {
		t.Fatalf("want 1 VIBE-DEP-002 for floating * with no lockfile, got %d (counts=%v)", counts["VIBE-DEP-002"], counts)
	}
	if counts["VIBE-DEP-001"] != 0 {
		t.Fatalf("did not expect VIBE-DEP-001 for a registry float, got %d", counts["VIBE-DEP-001"])
	}
}

func TestDepProvenance_FloatingWithLockfileSuppressed(t *testing.T) {
	dir := t.TempDir()
	depWriteFile(t, dir, "package.json", `{
  "dependencies": {
    "bar": "*"
  }
}`)
	depWriteFile(t, dir, "package-lock.json", `{"lockfileVersion": 3}`)
	res, err := RunDependencyProvenance(dir)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	findings := depFindings(t, res)
	counts := depCheckIDs(t, findings)
	if counts["VIBE-DEP-002"] != 0 {
		t.Fatalf("lockfile present should suppress VIBE-DEP-002, got %d", counts["VIBE-DEP-002"])
	}
	if len(findings) != 0 {
		t.Fatalf("want no findings for floating dep with lockfile, got %d", len(findings))
	}
}

func TestDepProvenance_OverridesRedirection(t *testing.T) {
	dir := t.TempDir()
	depWriteFile(t, dir, "package.json", `{
  "dependencies": {
    "lodash": "^4.17.21"
  },
  "overrides": {
    "lodash": "git+https://github.com/attacker/lodash.git"
  }
}`)
	// Add a lockfile so the only finding is the override redirection.
	depWriteFile(t, dir, "pnpm-lock.yaml", "lockfileVersion: '6.0'\n")
	res, err := RunDependencyProvenance(dir)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	findings := depFindings(t, res)
	counts := depCheckIDs(t, findings)
	if counts["VIBE-DEP-003"] != 1 {
		t.Fatalf("want 1 VIBE-DEP-003 for overrides redirection, got %d (counts=%v)", counts["VIBE-DEP-003"], counts)
	}
	for _, f := range findings {
		m := f.(map[string]interface{})
		if m["check_id"] == "VIBE-DEP-003" && m["cwe"] != "CWE-494" {
			t.Fatalf("VIBE-DEP-003 cwe = %v, want CWE-494", m["cwe"])
		}
	}
}

func TestDepProvenance_CleanSemverWithLockfile(t *testing.T) {
	dir := t.TempDir()
	depWriteFile(t, dir, "package.json", `{
  "dependencies": {
    "react": "18.2.0",
    "left-pad": "^1.3.0",
    "aliased": "npm:string-width@4.2.3"
  },
  "devDependencies": {
    "typescript": "~5.4.0"
  }
}`)
	depWriteFile(t, dir, "yarn.lock", "# yarn lockfile v1\n")
	res, err := RunDependencyProvenance(dir)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	findings := depFindings(t, res)
	if len(findings) != 0 {
		t.Fatalf("all-semver manifest with lockfile should be clean, got %d findings: %v", len(findings), findings)
	}
}

func TestDepProvenance_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	res, err := RunDependencyProvenance(dir)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	findings := depFindings(t, res)
	if len(findings) != 0 {
		t.Fatalf("empty dir should yield no findings, got %d", len(findings))
	}
}

func TestDepProvenance_MultipleSourcesAndSections(t *testing.T) {
	dir := t.TempDir()
	depWriteFile(t, dir, "package.json", `{
  "dependencies": {
    "a": "file:../local-pkg",
    "b": "https://example.com/b.tgz",
    "pinned": "2.0.0"
  },
  "devDependencies": {
    "c": "latest",
    "d": "gitlab:group/proj"
  }
}`)
	// No lockfile present.
	res, err := RunDependencyProvenance(dir)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	findings := depFindings(t, res)
	counts := depCheckIDs(t, findings)
	// a (file:), b (https), d (gitlab:) -> three 001; c (latest) -> one 002;
	// pinned 2.0.0 -> clean.
	if counts["VIBE-DEP-001"] != 3 {
		t.Fatalf("want 3 VIBE-DEP-001, got %d (counts=%v)", counts["VIBE-DEP-001"], counts)
	}
	if counts["VIBE-DEP-002"] != 1 {
		t.Fatalf("want 1 VIBE-DEP-002 (latest), got %d (counts=%v)", counts["VIBE-DEP-002"], counts)
	}
}
