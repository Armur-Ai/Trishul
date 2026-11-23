package checkrun

import (
	"strings"
	"testing"
	"time"

	"github.com/Armur-Ai/Trishul/internal/findings"
)

func mk(rule string, sev findings.Severity, cat string) findings.Finding {
	return findings.New(findings.Finding{RuleID: rule, Severity: sev, Category: cat, Message: rule + " msg", Location: findings.Location{Path: "a.go", StartLine: 1}})
}

func TestRender_Headline(t *testing.T) {
	in := Input{
		New:     []findings.Finding{mk("A", findings.SeverityCritical, "injection"), mk("B", findings.SeverityHigh, "auth")},
		Blocked: true, Version: "1.2.3", Duration: 2 * time.Second,
	}
	out := Render(in)
	if !strings.Contains(out, "2 new issues (1 critical, 1 high) · gate failed") {
		t.Errorf("headline wrong:\n%s", out)
	}
	if !strings.Contains(out, "Trishul 1.2.3") {
		t.Errorf("footer missing version:\n%s", out)
	}
}

func TestRender_NoIssues(t *testing.T) {
	out := Render(Input{Blocked: false})
	if !strings.Contains(out, "No new issues") {
		t.Errorf("expected clean headline:\n%s", out)
	}
}

func TestRender_SectionsAndGrouping(t *testing.T) {
	in := Input{
		New:        []findings.Finding{mk("A", findings.SeverityHigh, "injection"), mk("B", findings.SeverityLow, "auth")},
		Fixed:      []findings.Finding{mk("OLD", findings.SeverityMedium, "x")},
		Suppressed: []SuppressInfo{{RuleID: "S", Path: "a.go", Line: 3, Reason: "accepted"}},
	}
	out := Render(in)
	for _, want := range []string{"## New findings", "### auth", "### injection", "## Fixed (1)", "~~OLD~~", "## Suppressed in this PR (1)", "accepted"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

func TestRender_Truncates(t *testing.T) {
	var many []findings.Finding
	for i := 0; i < 5000; i++ {
		many = append(many, mk("RULE", findings.SeverityHigh, "c"))
	}
	out := Render(Input{New: many})
	if len(out) > MaxBody {
		t.Errorf("body exceeds limit: %d > %d", len(out), MaxBody)
	}
	if !strings.Contains(out, "truncated") {
		t.Error("expected truncation notice")
	}
}
