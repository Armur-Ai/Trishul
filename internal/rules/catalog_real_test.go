package rules

import "testing"

// repoRulesDir is the real catalog directory relative to this package.
const repoRulesDir = "../../rules"

// TestRealCatalog_LoadsAndValidates guards every committed rule YAML: it must
// parse, have no duplicate ids, and pass field/enum validation. This is the
// P1.2 catalog gate — a malformed or incomplete rule entry fails CI here.
func TestRealCatalog_LoadsAndValidates(t *testing.T) {
	c, err := LoadCatalog(repoRulesDir)
	if err != nil {
		t.Fatalf("load real catalog: %v", err)
	}
	if c.Len() == 0 {
		t.Fatal("real catalog is empty")
	}
	if errs := c.Validate(); len(errs) != 0 {
		for _, e := range errs {
			t.Errorf("catalog: %v", e)
		}
	}
	t.Logf("real catalog: %d rules", c.Len())
}

// TestRealCatalog_EveryRuleHasExamplesAndFix encourages complete, useful entries
// without hard-failing on the few that legitimately have none: it reports how
// many rules lack a fix or examples so the gap is visible in CI logs.
func TestRealCatalog_Completeness(t *testing.T) {
	c, err := LoadCatalog(repoRulesDir)
	if err != nil {
		t.Fatal(err)
	}
	var noFix, noExample int
	for _, d := range c.All() {
		if d.Fix == "" {
			noFix++
		}
		if d.Examples.Bad == "" && d.Examples.Good == "" {
			noExample++
		}
	}
	t.Logf("rules without fix: %d/%d; without examples: %d/%d", noFix, c.Len(), noExample, c.Len())
}
