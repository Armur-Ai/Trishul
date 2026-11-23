package prgate

import "testing"

func TestContextMultiplierFor(t *testing.T) {
	if ContextMultiplierFor("src/main.go") != 1.0 {
		t.Error("source should be full weight")
	}
	if ContextMultiplierFor("src/main_test.go") >= 1.0 {
		t.Error("test file should be discounted")
	}
}

func TestGatePipeline_DenoisesAndBudgets(t *testing.T) {
	var fs []Finding
	// 5 of one rule in one file -> should group to 1; plus a critical elsewhere.
	for i := 1; i <= 5; i++ {
		fs = append(fs, Finding{RuleID: "VIBE-DEP-001", Severity: "medium", Path: "a.go", Line: i, Fingerprint: fpOf(i)})
	}
	fs = append(fs, Finding{RuleID: "AGENT-EXEC-002", Severity: "critical", Path: "b.go", Line: 1, Fingerprint: "crit"})
	s := &Scan{Findings: fs}

	b := s.GatePipeline(10, 25)
	total := len(b.Inline) + len(b.Summary) + len(b.Overflow)
	if total != 2 {
		t.Fatalf("expected 2 after grouping (1 grouped + 1 crit), got %d", total)
	}
	// Critical should rank first inline.
	if len(b.Inline) == 0 || b.Inline[0].RuleID != "AGENT-EXEC-002" {
		t.Errorf("critical should be top inline: %+v", b.Inline)
	}
}

func TestGatePipeline_TestFilesSinkBelowSource(t *testing.T) {
	s := &Scan{Findings: []Finding{
		{RuleID: "R", Severity: "high", Path: "x_test.go", Line: 1, Fingerprint: "t"},
		{RuleID: "R", Severity: "high", Path: "x.go", Line: 1, Fingerprint: "s"},
	}}
	b := s.GatePipeline(1, 25)
	if len(b.Inline) != 1 || b.Inline[0].Location.Path != "x.go" {
		t.Errorf("source finding should outrank the test-file one: %+v", b.Inline)
	}
}

func fpOf(i int) string { return "fp" + string(rune('0'+i)) }
