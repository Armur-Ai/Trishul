package findings

import "testing"

func TestDedupe_CrossAnalyzerMerge(t *testing.T) {
	fs := []Finding{
		{Analyzer: "semgrep", RuleID: "A", CWE: []string{"CWE-89"}, Confidence: 0.6, Location: Location{Path: "a.go", StartLine: 10}},
		{Analyzer: "vibe", RuleID: "B", CWE: []string{"CWE-89"}, Confidence: 0.9, Location: Location{Path: "a.go", StartLine: 11}},
	}
	out := Dedupe(fs)
	if len(out) != 1 {
		t.Fatalf("want 1 merged, got %d", len(out))
	}
	if out[0].Analyzer != "vibe" { // higher confidence kept
		t.Errorf("kept %s want vibe", out[0].Analyzer)
	}
	if len(out[0].AlsoReportedBy) != 1 || out[0].AlsoReportedBy[0] != "semgrep" {
		t.Errorf("also_reported_by=%v", out[0].AlsoReportedBy)
	}
}

func TestDedupe_NoMergeWithoutSharedCWE(t *testing.T) {
	fs := []Finding{
		{Analyzer: "x", CWE: []string{"CWE-89"}, Location: Location{Path: "a.go", StartLine: 10}},
		{Analyzer: "y", CWE: []string{"CWE-79"}, Location: Location{Path: "a.go", StartLine: 10}},
	}
	if out := Dedupe(fs); len(out) != 2 {
		t.Errorf("different CWE should not merge: %d", len(out))
	}
}

func TestDedupe_NoMergeWhenNoCWE(t *testing.T) {
	fs := []Finding{
		{Analyzer: "x", Location: Location{Path: "a.go", StartLine: 10}},
		{Analyzer: "y", Location: Location{Path: "a.go", StartLine: 10}},
	}
	if out := Dedupe(fs); len(out) != 2 {
		t.Errorf("no-CWE findings must not merge: %d", len(out))
	}
}

func TestDedupe_FarApartNotMerged(t *testing.T) {
	fs := []Finding{
		{Analyzer: "x", CWE: []string{"CWE-89"}, Location: Location{Path: "a.go", StartLine: 10}},
		{Analyzer: "y", CWE: []string{"CWE-89"}, Location: Location{Path: "a.go", StartLine: 20}},
	}
	if out := Dedupe(fs); len(out) != 2 {
		t.Errorf("lines >1 apart should not merge: %d", len(out))
	}
}
