package sarif

import (
	"strings"
	"testing"
)

func TestFromScanResults_IncludesAgentSecurity(t *testing.T) {
	results := map[string]interface{}{
		"agent_security": []interface{}{
			map[string]interface{}{
				"check_id": "AGENT-INSTR-001", "message": "instruction override attempt",
				"severity": "HIGH", "path": "CLAUDE.md", "line": 3,
				"trust_boundary": "untrusted instructions -> agent behavior", "confidence": "MEDIUM",
			},
		},
	}
	run := FromScanResults(results, "test").Runs[0]
	var found *Result
	for i := range run.Results {
		if run.Results[i].RuleID == "AGENT-INSTR-001" {
			found = &run.Results[i]
		}
	}
	if found == nil {
		t.Fatal("expected an AGENT-INSTR-001 result in SARIF")
	}
	if !strings.Contains(found.Message.Text, "trust boundary") {
		t.Errorf("expected trust boundary in message, got %q", found.Message.Text)
	}
	if found.PartialFingerprints["trishul/v1"] == "" {
		t.Error("expected a partial fingerprint")
	}
}
