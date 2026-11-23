package findings

import "testing"

func TestBaseline_HasAndNew(t *testing.T) {
	existing := New(Finding{RuleID: "R", Location: Location{Path: "old.go", StartLine: 1}, Snippet: "exec(x)"})
	b := NewBaseline([]string{existing.FingerprintV2})

	same := New(Finding{RuleID: "R", Location: Location{Path: "old.go", StartLine: 1}, Snippet: "exec(x)"})
	if same.IsNew(b, nil) {
		t.Error("identical finding should not be new")
	}
	fresh := New(Finding{RuleID: "R", Location: Location{Path: "old.go", StartLine: 1}, Snippet: "spawn(y)"})
	if !fresh.IsNew(b, nil) {
		t.Error("structurally different finding should be new")
	}
}

func TestBaseline_RenameTracking(t *testing.T) {
	old := New(Finding{RuleID: "R", Location: Location{Path: "pkg/old.go", StartLine: 5}, Snippet: "exec(x)"})
	b := NewBaseline([]string{old.FingerprintV2})

	// Same finding now at a renamed path — would be "new" without rename tracking.
	moved := New(Finding{RuleID: "R", Location: Location{Path: "pkg/new.go", StartLine: 5}, Snippet: "exec(x)"})
	if moved.IsNew(b, nil) == false {
		t.Error("precondition: without renames it should look new")
	}
	renames := map[string]string{"pkg/new.go": "pkg/old.go"}
	if moved.IsNew(b, renames) {
		t.Error("rename-tracked finding should not be new")
	}
}

func TestBaseline_ExtraV1Fingerprint(t *testing.T) {
	b := NewBaseline([]string{"legacyv1hash"})
	f := New(Finding{RuleID: "R", Location: Location{Path: "a.go", StartLine: 1}, Snippet: "x"})
	if f.IsNew(b, nil) == false {
		t.Error("precondition: v2 not in baseline so looks new")
	}
	if f.IsNew(b, nil, "legacyv1hash") {
		t.Error("finding whose v1 fp is in baseline should not be new")
	}
}

func TestNewOnly(t *testing.T) {
	a := New(Finding{RuleID: "R", Location: Location{Path: "a.go", StartLine: 1}, Snippet: "x"})
	bb := New(Finding{RuleID: "R", Location: Location{Path: "a.go", StartLine: 2}, Snippet: "y"})
	base := NewBaseline([]string{a.FingerprintV2})
	out := NewOnly([]Finding{a, bb}, base, nil)
	if len(out) != 1 || out[0].Snippet != "y" {
		t.Errorf("NewOnly wrong: %+v", out)
	}
}

func TestBaseline_NilIsAllNew(t *testing.T) {
	f := New(Finding{RuleID: "R", Location: Location{Path: "a.go", StartLine: 1}})
	if !f.IsNew(nil, nil) {
		t.Error("nil baseline => everything new")
	}
}
