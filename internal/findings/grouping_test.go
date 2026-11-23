package findings

import "testing"

func mk(rule, path string, line int, sev Severity) Finding {
	return Finding{RuleID: rule, Analyzer: "x", Severity: sev, Confidence: 0.6, Location: Location{Path: path, StartLine: line}}
}

func TestGroupPerFile(t *testing.T) {
	var fs []Finding
	for i := 1; i <= 5; i++ { // 5 of RULE in a.go -> grouped (>3)
		fs = append(fs, mk("RULE", "a.go", i*2, SeverityMedium))
	}
	fs = append(fs, mk("RULE", "b.go", 1, SeverityLow)) // single in b.go -> kept
	out := GroupPerFile(fs, 3)
	if len(out) != 2 {
		t.Fatalf("want 2 (grouped a.go + single b.go), got %d", len(out))
	}
	var grouped *Finding
	for i := range out {
		if out[i].Location.Path == "a.go" {
			grouped = &out[i]
		}
	}
	if grouped == nil || grouped.Count != 5 {
		t.Fatalf("a.go count=%v", grouped)
	}
	if len(grouped.GroupedLines) != 5 || grouped.GroupedLines[0] != 2 {
		t.Errorf("lines=%v", grouped.GroupedLines)
	}
}

func TestGroupPerFile_BelowThresholdUnchanged(t *testing.T) {
	fs := []Finding{mk("R", "a.go", 1, SeverityLow), mk("R", "a.go", 2, SeverityLow)}
	if out := GroupPerFile(fs, 3); len(out) != 2 {
		t.Errorf("2 (<=3) should stay separate: %d", len(out))
	}
}

func TestClusterByRule(t *testing.T) {
	var fs []Finding
	for i := 0; i < 25; i++ { // RULE in 25 files -> clustered (>20)
		fs = append(fs, mk("RULE", "f"+string(rune('a'+i%26))+string(rune('0'+i/26))+".go", 1, SeverityHigh))
	}
	fs = append(fs, mk("OTHER", "x.go", 1, SeverityLow))
	out := ClusterByRule(fs, 20)
	ruleCount := 0
	for _, f := range out {
		if f.RuleID == "RULE" {
			ruleCount++
			if f.Count != 25 {
				t.Errorf("cluster count=%d", f.Count)
			}
		}
	}
	if ruleCount != 1 {
		t.Errorf("RULE should collapse to 1 row, got %d", ruleCount)
	}
}

func TestApplyBudget(t *testing.T) {
	var fs []Finding
	for i := 0; i < 40; i++ {
		fs = append(fs, mk("R", "a.go", i, SeverityHigh))
	}
	b := ApplyBudget(fs, nil, 10, 25)
	if len(b.Inline) != 10 || len(b.Summary) != 25 || len(b.Overflow) != 5 {
		t.Errorf("budget split wrong: inline=%d summary=%d overflow=%d", len(b.Inline), len(b.Summary), len(b.Overflow))
	}
}

func TestApplyBudget_PrioritizesHighest(t *testing.T) {
	fs := []Finding{
		mk("low", "a.go", 1, SeverityLow),
		mk("crit", "a.go", 2, SeverityCritical),
	}
	b := ApplyBudget(fs, nil, 1, 1)
	if len(b.Inline) != 1 || b.Inline[0].RuleID != "crit" {
		t.Errorf("inline should be the critical: %+v", b.Inline)
	}
}
