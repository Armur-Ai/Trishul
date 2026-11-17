package agentsec

import "testing"

func TestCorrelate_BuildsChainWhenEntryAndActionPresent(t *testing.T) {
	findings := []AgentFinding{
		{CheckID: "AGENT-INJ-002", Title: "README directive", File: "README.md", Line: 4, EnabledAction: "add dependency"},
		{CheckID: "AGENT-EXEC-001", Title: "malicious postinstall", File: "package.json", Line: 9, EnabledAction: "curl | sh to evil.example"},
	}
	chains := correlate(".", findings)
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain finding, got %d", len(chains))
	}
	c := chains[0]
	if c.CheckID != "AGENT-CHAIN-001" || c.Severity != "CRITICAL" || c.Confidence != "HIGH" {
		t.Errorf("unexpected chain finding: %+v", c)
	}
	if len(c.Evidence) < 2 {
		t.Errorf("chain must reference both the entry point and the action")
	}
}

func TestCorrelate_NoChainWithoutBothSides(t *testing.T) {
	// Only an entry point, no enabled action -> no chain (avoid false alarms).
	only := []AgentFinding{{CheckID: "AGENT-INJ-001", File: "a.go", Line: 1}}
	if got := correlate(".", only); len(got) != 0 {
		t.Errorf("no chain expected without an action, got %d", len(got))
	}
	// Only an action, no entry point -> no chain.
	act := []AgentFinding{{CheckID: "AGENT-EXEC-001", File: "package.json", Line: 1}}
	if got := correlate(".", act); len(got) != 0 {
		t.Errorf("no chain expected without an entry point, got %d", len(got))
	}
}
