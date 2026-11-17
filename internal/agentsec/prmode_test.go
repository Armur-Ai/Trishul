package agentsec

import "testing"

func TestFilterToChangedFiles(t *testing.T) {
	fs := []AgentFinding{
		{CheckID: "AGENT-INJ-001", File: "src/a.go"},
		{CheckID: "AGENT-EXEC-001", File: "package.json"},
		{CheckID: "AGENT-CHAIN-001", File: "README.md"}, // unchanged, but always kept
	}
	got := FilterToChangedFiles(fs, []string{"package.json"})
	// package.json (changed) + the chain = 2
	if len(got) != 2 {
		t.Fatalf("want 2 (changed + chain), got %d", len(got))
	}
	var sawChain, sawPkg bool
	for _, f := range got {
		if f.CheckID == "AGENT-CHAIN-001" {
			sawChain = true
		}
		if f.File == "package.json" {
			sawPkg = true
		}
	}
	if !sawChain || !sawPkg {
		t.Errorf("expected the changed file and the chain to survive")
	}
	// empty changed set -> unchanged
	if len(FilterToChangedFiles(fs, nil)) != 3 {
		t.Errorf("nil changed set should return all findings")
	}
}
