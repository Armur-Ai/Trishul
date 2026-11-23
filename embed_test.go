package trishul

import "testing"

func TestEmbeddedCatalogLoads(t *testing.T) {
	c, err := Catalog()
	if err != nil {
		t.Fatalf("load embedded catalog: %v", err)
	}
	if c.Len() == 0 {
		t.Fatal("embedded catalog is empty")
	}
	if errs := c.Validate(); len(errs) != 0 {
		t.Errorf("embedded catalog invalid: %v", errs)
	}
	// a known rule should be present
	if _, ok := c.Get("AGENT-EXEC-002"); !ok {
		t.Error("expected AGENT-EXEC-002 in embedded catalog")
	}
	t.Logf("embedded catalog: %d rules", c.Len())
}

func TestRulesFS(t *testing.T) {
	entries, err := RulesFS().ReadDir("rules")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Error("no embedded rule files")
	}
}
