package prgate

import (
	"testing"

	"github.com/Armur-Ai/Trishul/internal/findings"
)

func TestToV2(t *testing.T) {
	f := Finding{
		RuleID:      "AGENT-EXEC-002",
		Severity:    "high",
		Path:        "a.json",
		Line:        12,
		Message:     "hook runs curl | sh",
		Fingerprint: "gatefp123",
	}
	v := f.ToV2()
	if v.RuleID != "AGENT-EXEC-002" || v.Analyzer != "agentsec" {
		t.Fatalf("rule/analyzer: %+v", v)
	}
	if v.Severity != findings.SeverityHigh {
		t.Errorf("severity=%q (uppercased?)", v.Severity)
	}
	if v.Location.Path != "a.json" || v.Location.StartLine != 12 {
		t.Errorf("location=%+v", v.Location)
	}
	if v.FingerprintV2 != "gatefp123" {
		t.Errorf("gate fingerprint not preserved: %q", v.FingerprintV2)
	}
}

func TestAnalyzerFor(t *testing.T) {
	cases := map[string]string{
		"AGENT-X":           "agentsec",
		"EXPLOIT-Y":         "exploitability",
		"VIBE-Z":            "vibe",
		"SUPABASE-RLS-001":  "supabase",
		"FIREBASE-001":      "firebase",
		"CLIENT-SECRET-001": "secrets",
		"WHATEVER":          "trishul",
	}
	for id, want := range cases {
		if got := analyzerFor(id); got != want {
			t.Errorf("analyzerFor(%q)=%q want %q", id, got, want)
		}
	}
}

func TestV2Findings(t *testing.T) {
	s := &Scan{Findings: []Finding{
		{RuleID: "A", Severity: "low", Path: "a.go", Line: 1, Fingerprint: "f1"},
		{RuleID: "B", Severity: "critical", Path: "b.go", Line: 2, Fingerprint: "f2"},
	}}
	v := s.V2Findings()
	if len(v) != 2 || v[1].Severity != findings.SeverityCritical {
		t.Errorf("v2 findings wrong: %+v", v)
	}
}
