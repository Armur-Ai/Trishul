package agentsec

import "testing"

func TestToFindingMaps(t *testing.T) {
	got := ToFindingMaps([]AgentFinding{{
		CheckID: "AGENT-INSTR-001", Title: "override attempt", Severity: "HIGH",
		Confidence: "MEDIUM", File: "CLAUDE.md", Line: 3, CWE: "CWE-94",
		TrustBoundary: "instructions -> behavior",
	}})
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	m := got[0].(map[string]interface{})
	if m["check_id"] != "AGENT-INSTR-001" || m["severity"] != "HIGH" || m["path"] != "CLAUDE.md" {
		t.Errorf("unexpected map: %+v", m)
	}
	if m["trust_boundary"] != "instructions -> behavior" {
		t.Errorf("trust_boundary not carried")
	}
}
