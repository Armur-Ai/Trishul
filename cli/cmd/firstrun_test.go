package cmd

import (
	"strings"
	"testing"

	"github.com/Armur-Ai/Trishul/internal/prgate"
)

func TestRunFirstRun_CleanDir(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	code := runFirstRun(dir, &b)
	if code != 0 {
		t.Errorf("exit=%d want 0", code)
	}
	out := b.String()
	if !strings.Contains(out, "Grade:") || !strings.Contains(out, "Next steps:") {
		t.Errorf("first-run output missing sections:\n%s", out)
	}
	if !strings.Contains(out, "trishul init github") {
		t.Errorf("next-steps box missing commands:\n%s", out)
	}
}

func TestTopFindings_OrdersBySeverityAndCaps(t *testing.T) {
	fs := []prgate.Finding{
		{RuleID: "low", Severity: "low"},
		{RuleID: "crit", Severity: "critical"},
		{RuleID: "med", Severity: "medium"},
		{RuleID: "high", Severity: "high"},
	}
	top := topFindings(fs, 2)
	if len(top) != 2 {
		t.Fatalf("cap failed: %d", len(top))
	}
	if top[0].RuleID != "crit" || top[1].RuleID != "high" {
		t.Errorf("order wrong: %s, %s", top[0].RuleID, top[1].RuleID)
	}
}
