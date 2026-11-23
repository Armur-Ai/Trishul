package prgate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplySuppressions(t *testing.T) {
	root := t.TempDir()
	// line 1: a suppressed finding (marker on the same line), line 2: a kept one.
	src := "danger() // trishul-ignore[R1]: accepted, TICKET-9\nother()\n"
	if err := os.WriteFile(filepath.Join(root, "a.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	fs := []Finding{
		{RuleID: "R1", Path: "a.go", Line: 1},
		{RuleID: "R2", Path: "a.go", Line: 2},
	}
	kept, supp := ApplySuppressions(fs, root)
	if len(kept) != 1 || kept[0].RuleID != "R2" {
		t.Fatalf("kept wrong: %+v", kept)
	}
	if len(supp) != 1 || supp[0].Finding.RuleID != "R1" || supp[0].Reason == "" {
		t.Fatalf("suppressed wrong: %+v", supp)
	}
}

func TestApplySuppressions_WrongRuleNotSuppressed(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "a.go"), []byte("x() // trishul-ignore[R1]: r\n"), 0o644)
	kept, supp := ApplySuppressions([]Finding{{RuleID: "R2", Path: "a.go", Line: 1}}, root)
	if len(kept) != 1 || len(supp) != 0 {
		t.Errorf("rule-specific marker must not suppress a different rule: kept=%d supp=%d", len(kept), len(supp))
	}
}

func TestApplySuppressions_MissingFileKeeps(t *testing.T) {
	kept, supp := ApplySuppressions([]Finding{{RuleID: "R", Path: "nope.go", Line: 1}}, t.TempDir())
	if len(kept) != 1 || len(supp) != 0 {
		t.Errorf("missing file should fail-open (keep): kept=%d supp=%d", len(kept), len(supp))
	}
}
