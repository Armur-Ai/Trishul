package rules

import "testing"

func TestLoadCatalog(t *testing.T) {
	c, err := LoadCatalog("testdata/catalog")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Len() != 2 {
		t.Fatalf("len=%d want 2 (%v)", c.Len(), c.IDs())
	}
	// sorted order
	ids := c.IDs()
	if ids[0] != "AGENT-EXEC-002" || ids[1] != "VIBE-007" {
		t.Errorf("ids=%v", ids)
	}

	d, ok := c.Get("AGENT-EXEC-002")
	if !ok {
		t.Fatal("missing AGENT-EXEC-002")
	}
	if d.DefaultSeverity != "HIGH" || d.DefaultConfidence != 0.85 || d.Maturity != MaturityStable {
		t.Errorf("fields: %+v", d)
	}
	if len(d.CWE) != 2 || d.CWE[0] != "CWE-77" {
		t.Errorf("cwe=%v", d.CWE)
	}
	if d.Examples.Bad == "" || d.ModeDefault != ModeBlock {
		t.Errorf("examples/mode: %+v", d.Examples)
	}

	// single-document form
	v, ok := c.Get("VIBE-007")
	if !ok || v.Maturity != MaturityBeta || v.ModeDefault != ModeComment {
		t.Errorf("single-doc rule wrong: %+v", v)
	}
}

func TestCatalogValidate_Clean(t *testing.T) {
	c, err := LoadCatalog("testdata/catalog")
	if err != nil {
		t.Fatal(err)
	}
	if errs := c.Validate(); len(errs) != 0 {
		t.Errorf("unexpected validation errors: %v", errs)
	}
}

func TestCatalogValidate_CatchesBadFields(t *testing.T) {
	c := &Catalog{byID: map[string]RuleDef{}, order: []string{"BAD"}}
	c.byID["BAD"] = RuleDef{ID: "BAD", DefaultSeverity: "nope", DefaultConfidence: 5, Maturity: "shaky", ModeDefault: "explode"}
	errs := c.Validate()
	if len(errs) < 4 {
		t.Errorf("want >=4 errors (title,severity,confidence,maturity,mode), got %d: %v", len(errs), errs)
	}
}
