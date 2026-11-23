package precision

import "testing"

func TestResolve_FingerprintFastPath(t *testing.T) {
	found := []Found{{RuleID: "R", Path: "a.go", Line: 10, Fingerprint: "fp1"}}
	labels := []Label{{RuleID: "R", Path: "a.go", Line: 999, Verdict: FP, FingerprintV2: "fp1"}}
	matched, unlabeled := Resolve(found, labels)
	if len(matched) != 1 || len(unlabeled) != 0 {
		t.Fatalf("fingerprint match failed: matched=%d unlabeled=%d", len(matched), len(unlabeled))
	}
}

func TestResolve_LocationFallbackWithinTolerance(t *testing.T) {
	found := []Found{{RuleID: "R", Path: "a.go", Line: 12, Fingerprint: "different"}}
	labels := []Label{{RuleID: "R", Path: "a.go", Line: 10, Verdict: TP, FingerprintV2: "old"}}
	matched, unlabeled := Resolve(found, labels)
	if len(matched) != 1 || len(unlabeled) != 0 {
		t.Fatalf("location fallback (±3) failed: matched=%d unlabeled=%d", len(matched), len(unlabeled))
	}
}

func TestResolve_OutsideTolerance(t *testing.T) {
	found := []Found{{RuleID: "R", Path: "a.go", Line: 20, Fingerprint: "x"}}
	labels := []Label{{RuleID: "R", Path: "a.go", Line: 10, Verdict: TP}}
	matched, unlabeled := Resolve(found, labels)
	if len(matched) != 0 || len(unlabeled) != 1 {
		t.Fatalf("far finding should be unlabeled: matched=%d unlabeled=%d", len(matched), len(unlabeled))
	}
}

func TestResolve_EachLabelUsedOnce(t *testing.T) {
	found := []Found{
		{RuleID: "R", Path: "a.go", Line: 10, Fingerprint: "x"},
		{RuleID: "R", Path: "a.go", Line: 11, Fingerprint: "y"},
	}
	labels := []Label{{RuleID: "R", Path: "a.go", Line: 10, Verdict: TP}}
	matched, unlabeled := Resolve(found, labels)
	if len(matched) != 1 || len(unlabeled) != 1 {
		t.Fatalf("label reused or miscounted: matched=%d unlabeled=%d", len(matched), len(unlabeled))
	}
}

func TestFoundByRule(t *testing.T) {
	m := FoundByRule([]Found{{RuleID: "R", Fingerprint: "a"}, {RuleID: "R", Fingerprint: "b"}, {RuleID: "S", Fingerprint: "c"}})
	if len(m["R"]) != 2 || len(m["S"]) != 1 {
		t.Errorf("group wrong: %v", m)
	}
}
