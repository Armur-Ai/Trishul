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

func TestPermIsWildcard(t *testing.T) {
	yes := []string{"*", "all", "allow-all", "Bash(*)", "Bash(:*)"}
	no := []string{"Read", "Bash(git status)", "Grep(foo)"}
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
