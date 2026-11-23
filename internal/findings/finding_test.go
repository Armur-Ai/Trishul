package findings

import "testing"

func TestBandFor(t *testing.T) {
	cases := []struct {
		c    float64
		want ConfidenceBand
	}{
		{1.0, BandHigh}, {0.8, BandHigh}, {0.79, BandMedium},
		{0.5, BandMedium}, {0.49, BandLow}, {0.0, BandLow},
	}
	for _, tc := range cases {
		if got := BandFor(tc.c); got != tc.want {
			t.Errorf("BandFor(%v)=%q want %q", tc.c, got, tc.want)
		}
	}
}

func TestFinalize_DerivesBandEndlineFingerprint(t *testing.T) {
	f := New(Finding{
		RuleID:     "VIBE-001",
		Analyzer:   "vibe",
		Severity:   SeverityHigh,
		Confidence: 0.9,
		Location:   Location{Path: "a.go", StartLine: 10},
		Snippet:    "exec(userInput)",
	})
	if f.Band != BandHigh {
		t.Errorf("band=%q want high", f.Band)
	}
	if f.Location.EndLine != 10 {
		t.Errorf("endline=%d want 10 (defaults to start)", f.Location.EndLine)
	}
	if f.FingerprintV2 == "" {
		t.Error("fingerprint not computed")
	}
}

func TestFinalize_ClampsConfidence(t *testing.T) {
	if got := New(Finding{Confidence: 2.0}).Confidence; got != 1.0 {
		t.Errorf("confidence not clamped high: %v", got)
	}
	if got := New(Finding{Confidence: -1}).Confidence; got != 0.0 {
		t.Errorf("confidence not clamped low: %v", got)
	}
}

func TestEnsureEvidence(t *testing.T) {
	// no evidence -> synthesized from snippet
	f := New(Finding{RuleID: "R", Snippet: "exec(x)", Message: "cmd injection", Location: Location{Path: "a.go", StartLine: 7}}).EnsureEvidence()
	if len(f.Evidence) != 1 || f.Evidence[0].Note != "exec(x)" || f.Evidence[0].Line != 7 {
		t.Fatalf("evidence not synthesized from snippet: %+v", f.Evidence)
	}
	// falls back to message when no snippet
	g := New(Finding{RuleID: "R", Message: "boom"}).EnsureEvidence()
	if g.Evidence[0].Note != "boom" {
		t.Errorf("want message fallback, got %q", g.Evidence[0].Note)
	}
	// existing evidence preserved
	h := Finding{Evidence: []EvidenceStep{{Note: "kept"}}}.EnsureEvidence()
	if len(h.Evidence) != 1 || h.Evidence[0].Note != "kept" {
		t.Errorf("existing evidence clobbered: %+v", h.Evidence)
	}
}
