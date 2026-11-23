package prgate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Armur-Ai/Trishul/internal/projcfg"
)

func TestRunGateV2_EndToEnd(t *testing.T) {
	root := t.TempDir()
	// a.go line 1 has a suppressed critical; b.go has a live critical.
	os.WriteFile(filepath.Join(root, "a.go"), []byte("boom() // trishul-ignore[CRIT-RULE]: accepted\n"), 0o644)
	os.WriteFile(filepath.Join(root, "b.go"), []byte("boom()\n"), 0o644)
	os.WriteFile(filepath.Join(root, "vendor.go"), []byte("x\n"), 0o644)

	scan := &Scan{Findings: []Finding{
		{RuleID: "CRIT-RULE", Severity: "critical", Path: "a.go", Line: 1, Fingerprint: "a"},
		{RuleID: "CRIT-RULE", Severity: "critical", Path: "b.go", Line: 1, Fingerprint: "b"},
		{RuleID: "NOISY", Severity: "high", Path: "vendor/x.go", Line: 1, Fingerprint: "c"},
		{RuleID: "DISABLED", Severity: "high", Path: "c.go", Line: 1, Fingerprint: "d"},
	}}

	cfg := projcfg.Default()
	cfg.Paths.Ignore = []string{"vendor/**"}
	no := false
	cfg.Rules = map[string]projcfg.RuleOverride{"DISABLED": {Enabled: &no}}

	res := RunGateV2(scan, root, cfg)

	// a.go finding suppressed; vendor ignored; DISABLED off -> only b.go remains.
	if len(res.Suppressed) != 1 || res.Suppressed[0].Finding.Path != "a.go" {
		t.Fatalf("suppressed wrong: %+v", res.Suppressed)
	}
	total := len(res.Inline) + len(res.Summary) + len(res.Overflow)
	if total != 1 {
		t.Fatalf("expected only b.go to surface, got %d", total)
	}
	if !res.Blocked || len(res.BlockingRuleIDs) != 1 || res.BlockingRuleIDs[0] != "CRIT-RULE" {
		t.Errorf("should be blocked by CRIT-RULE: %+v", res)
	}
}

func TestRunGateV2_CommentModeDoesNotBlock(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "b.go"), []byte("boom()\n"), 0o644)
	scan := &Scan{Findings: []Finding{{RuleID: "R", Severity: "critical", Path: "b.go", Line: 1, Fingerprint: "b"}}}
	cfg := projcfg.Default()
	cfg.Rules = map[string]projcfg.RuleOverride{"R": {Mode: "comment"}}
	res := RunGateV2(scan, root, cfg)
	if res.Blocked {
		t.Error("comment-mode rule should not block")
	}
	if len(res.Inline)+len(res.Summary) != 1 {
		t.Error("comment-mode finding should still be shown")
	}
}
