package autofix

import "testing"

func TestToSARIFFix(t *testing.T) {
	p := Patch{Path: "a.sql", StartLine: 10, EndLine: 10, Replacement: "ALTER TABLE t ENABLE ROW LEVEL SECURITY;"}
	fix := ToSARIFFix(p, "enable RLS")
	if fix.Description == nil || fix.Description.Text != "enable RLS" {
		t.Errorf("description wrong: %+v", fix.Description)
	}
	if len(fix.ArtifactChanges) != 1 {
		t.Fatalf("want 1 artifact change")
	}
	ac := fix.ArtifactChanges[0]
	if ac.ArtifactLocation.URI != "a.sql" {
		t.Errorf("uri=%q", ac.ArtifactLocation.URI)
	}
	r := ac.Replacements[0]
	if r.DeletedRegion.StartLine != 10 || r.DeletedRegion.EndLine != 10 {
		t.Errorf("region=%+v", r.DeletedRegion)
	}
	if r.InsertedContent == nil || r.InsertedContent.Text != p.Replacement {
		t.Errorf("inserted=%+v", r.InsertedContent)
	}
}

func TestToSARIFFix_Insertion(t *testing.T) {
	p := Patch{Path: "a.sql", StartLine: 5, EndLine: 4, Replacement: "x"} // insert before line 5
	fix := ToSARIFFix(p, "")
	if fix.Description != nil {
		t.Error("empty description should be nil")
	}
	if dr := fix.ArtifactChanges[0].Replacements[0].DeletedRegion; dr.StartLine != 5 || dr.EndLine != 4 {
		t.Errorf("insertion region=%+v", dr)
	}
}
