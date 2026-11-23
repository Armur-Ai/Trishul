package agentsec

import (
	"os"
	"path/filepath"
	"testing"
)

func permWrite(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func permHas(fs []AgentFinding, checkID string) *AgentFinding {
	for i := range fs {
		if fs[i].CheckID == checkID {
			return &fs[i]
		}
	}
	return nil
}

func TestScanPermissions_EscalationFlagged(t *testing.T) {
	dir := t.TempDir()
	// Multi-line allow-all array, auto-approve, and a dangerous flag together.
	permWrite(t, dir, ".claude/settings.json", `{
  "permissions": {
    "allow": [
      "*"
    ]
  },
  "autoApprove": true,
  "hooks": {
    "preToolUse": "claude --dangerously-skip-permissions"
  }
}`)

	fs, err := scanPermissions(dir)
	if err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{"AGENT-PERM-001", "AGENT-PERM-002", "AGENT-PERM-003"} {
		if permHas(fs, id) == nil {
			t.Errorf("expected %s to be flagged, got %+v", id, fs)
		}
	}
	// allow-all carries CWE-732; flag/approval carry CWE-250.
	if f := permHas(fs, "AGENT-PERM-001"); f != nil && f.CWE != "CWE-732" {
		t.Errorf("PERM-001 CWE = %q, want CWE-732", f.CWE)
	}
	if f := permHas(fs, "AGENT-PERM-003"); f != nil && f.CWE != "CWE-250" {
		t.Errorf("PERM-003 CWE = %q, want CWE-250", f.CWE)
	}
	for _, f := range fs {
		if f.TrustBoundary == "" || f.AffectedWorkflow == "" || f.EntryPoint == "" || f.Line < 1 {
			t.Errorf("%s missing metadata: %+v", f.CheckID, f)
		}
	}
}

func TestScanPermissions_NormalSettingsClean(t *testing.T) {
	dir := t.TempDir()
	permWrite(t, dir, ".claude/settings.json", `{
  "permissions": {
    "allow": ["Read", "Grep", "Bash(git status)"],
    "deny": ["Bash(rm -rf:*)"]
  },
  "requireApproval": true
}`)

	fs, err := scanPermissions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Fatalf("ordinary settings should be clean, got %d findings: %+v", len(fs), fs)
	}
}

func TestScanPermissions_BypassMode(t *testing.T) {
	dir := t.TempDir()
	permWrite(t, dir, ".claude/settings.json", `{
  "defaultMode": "bypassPermissions"
}`)
	fs, err := scanPermissions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if permHas(fs, "AGENT-PERM-002") == nil {
		t.Fatalf("expected AGENT-PERM-002 for bypassPermissions mode, got %+v", fs)
	}
}

func TestScanPermissions_CIFlagAndSecurityDisable(t *testing.T) {
	dir := t.TempDir()
	permWrite(t, dir, ".github/workflows/agent.yml", `jobs:
  run:
    steps:
      - run: npx some-agent --no-sandbox --yolo
        env:
          NODE_TLS_REJECT_UNAUTHORIZED: "0"
`)
	fs, err := scanPermissions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if permHas(fs, "AGENT-PERM-003") == nil {
		t.Errorf("expected AGENT-PERM-003 for --no-sandbox, got %+v", fs)
	}
	if permHas(fs, "AGENT-PERM-004") == nil {
		t.Errorf("expected AGENT-PERM-004 for disabled TLS verification, got %+v", fs)
	}
}

func TestScanPermissions_ClaudeMdClean(t *testing.T) {
	dir := t.TempDir()
	permWrite(t, dir, "CLAUDE.md", "# Project\n\nRun tests with `go test ./...`. Be careful with migrations.\n")
	fs, err := scanPermissions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Fatalf("ordinary CLAUDE.md should be clean, got %+v", fs)
	}
}

// A wildcard in a committed project settings file is a shared escalation and
// must be flagged HIGH.
func TestScanPermissions_WildcardInProjectSettingsHigh(t *testing.T) {
	dir := t.TempDir()
	permWrite(t, dir, ".claude/settings.json", `{
  "permissions": {
    "allow": ["Bash(*)", "WebFetch(domain:*)"]
  }
}`)
	fs, err := scanPermissions(dir)
	if err != nil {
		t.Fatal(err)
	}
	f := permHas(fs, "AGENT-PERM-001")
	if f == nil {
		t.Fatalf("expected AGENT-PERM-001 for wildcard in committed .claude/settings.json, got %+v", fs)
	}
	if f.Severity != "HIGH" {
		t.Errorf("PERM-001 severity = %q, want HIGH", f.Severity)
	}
}

// The identical wildcard in a gitignored local override is a personal choice,
// not committed policy, and must NOT be flagged.
func TestScanPermissions_WildcardInLocalSettingsNotFlagged(t *testing.T) {
	dir := t.TempDir()
	permWrite(t, dir, ".claude/settings.local.json", `{
  "permissions": {
    "allow": ["Bash(*)", "WebFetch(domain:*)"]
  }
}`)
	fs, err := scanPermissions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if f := permHas(fs, "AGENT-PERM-001"); f != nil {
		t.Fatalf("wildcard in gitignored settings.local.json should not be flagged, got %+v", f)
	}
}

// A narrow, least-privilege allow-list is not an escalation.
func TestScanPermissions_NarrowAllowlistClean(t *testing.T) {
	dir := t.TempDir()
	permWrite(t, dir, ".claude/settings.json", `{
  "permissions": {
    "allow": ["Read", "Grep", "Bash(git status)", "WebFetch(domain:example.com)"]
  }
}`)
	fs, err := scanPermissions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if f := permHas(fs, "AGENT-PERM-001"); f != nil {
		t.Fatalf("narrow allow-list should produce no PERM-001 finding, got %+v", f)
	}
}

// Documentation and example configs illustrate settings; a wildcard there is
// not committed policy and must not be flagged.
func TestScanPermissions_DocsAndExamplesNotFlagged(t *testing.T) {
	dir := t.TempDir()
	permWrite(t, dir, "AGENTS.md", "Set `\"allow\": \"*\"` to allow every tool.\n")
	permWrite(t, dir, ".claude/settings.example.json", `{ "permissions": { "allow": ["*"] } }`)
	fs, err := scanPermissions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if f := permHas(fs, "AGENT-PERM-001"); f != nil {
		t.Fatalf("docs/example wildcard should not be flagged, got %+v", f)
	}
}

func TestPermIsProjectSettings(t *testing.T) {
	yes := []string{".claude/settings.json", "sub/.cursor/config.json", ".codeium/windsurf/settings.json", "settings.json", "app.settings.json"}
	no := []string{".claude/settings.local.json", "AGENTS.md", "docs/.claude/settings.json", ".claude/settings.example.json", "examples/settings.json", "testdata/settings.json", ".claude/hooks.yaml"}
	for _, s := range yes {
		if !permIsProjectSettings(s) {
			t.Errorf("permIsProjectSettings(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if permIsProjectSettings(s) {
			t.Errorf("permIsProjectSettings(%q) = true, want false", s)
		}
	}
}

func TestPermIsWildcard(t *testing.T) {
	yes := []string{"*", "all", "allow-all", "Bash(*)", "Bash(:*)", "Write(*)", "WebFetch(domain:*)"}
	no := []string{"Read", "Bash(git status)", "Grep(foo)", "WebFetch(domain:example.com)"}
	for _, s := range yes {
		if !permIsWildcard(s) {
			t.Errorf("permIsWildcard(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if permIsWildcard(s) {
			t.Errorf("permIsWildcard(%q) = true, want false", s)
		}
	}
}
