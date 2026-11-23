package findings

import "testing"

func TestSeverityWeight(t *testing.T) {
	if SeverityWeight(SeverityCritical) <= SeverityWeight(SeverityHigh) {
		t.Error("critical should outweigh high")
	}
	if SeverityWeight(SeverityInfo) >= SeverityWeight(SeverityLow) {
		t.Error("info should be below low")
	}
}

func TestContextMultiplier(t *testing.T) {
	if ContextMultiplier("source") != 1.0 {
		t.Error("source should be 1.0")
	}
	if ContextMultiplier("generated") >= ContextMultiplier("test") {
		t.Error("generated should discount more than test")
	}
	if ContextMultiplier("agent-surface") != 1.0 {
		t.Error("agent-surface counts fully")
	}
}

func TestPriority(t *testing.T) {
	f := Finding{Severity: SeverityHigh, Confidence: 0.5}
	// 0.8 * 0.5 * 1.0 = 0.4
	if got := f.Priority(1.0); got < 0.39 || got > 0.41 {
		t.Errorf("priority=%v want ~0.4", got)
	}
	// generated-file discount sinks it
	if f.Priority(0.15) >= f.Priority(1.0) {
		t.Error("context discount should lower priority")
	}
}

func TestRank_OrdersByPriority(t *testing.T) {
	fs := []Finding{
		{RuleID: "low-conf-crit", Severity: SeverityCritical, Confidence: 0.2, Location: Location{Path: "a.go", StartLine: 1}},
		{RuleID: "high-conf-high", Severity: SeverityHigh, Confidence: 0.95, Location: Location{Path: "b.go", StartLine: 1}},
		{RuleID: "crit-in-test", Severity: SeverityCritical, Confidence: 0.95, Location: Location{Path: "x_test.go", StartLine: 1}},
	}
	mult := func(path string) float64 {
		if path == "x_test.go" {
			return 0.4
		}
		return 1.0
	}
	ranked := Rank(fs, mult)
	// high-conf-high: .8*.95*1=.76 ; crit-in-test: 1*.95*.4=.38 ; low-conf-crit: 1*.2*1=.2
	if ranked[0].Finding.RuleID != "high-conf-high" {
		t.Errorf("top=%s", ranked[0].Finding.RuleID)
	}
	if ranked[2].Finding.RuleID != "low-conf-crit" {
		t.Errorf("bottom=%s", ranked[2].Finding.RuleID)
	}
}

func TestRank_NilMultiplier(t *testing.T) {
	fs := []Finding{{Severity: SeverityLow, Confidence: 1}}
	if r := Rank(fs, nil); len(r) != 1 || r[0].Priority != SeverityWeight(SeverityLow) {
		t.Errorf("nil multiplier should be 1.0: %+v", r)
	}
}
