package agent

import (
	"strings"
	"testing"
	"time"
)

func TestCollectAgentHighlights_ChainsFirst(t *testing.T) {
	v := []interface{}{
		map[string]interface{}{"check_id": "AGENT-INJ-001", "message": "injection", "severity": "MEDIUM", "path": "README.md", "line": 2},
		map[string]interface{}{"check_id": "AGENT-CHAIN-001", "message": "entry+action chain", "severity": "CRITICAL", "path": "package.json", "line": 5},
	}
	hs := collectAgentHighlights(v)
	if len(hs) != 2 {
		t.Fatalf("want 2 highlights, got %d", len(hs))
	}
	if !strings.Contains(hs[0], "AGENT-CHAIN-001") {
		t.Errorf("attack chain should be listed first, got %q", hs[0])
	}
	if collectAgentHighlights(nil) != nil {
		t.Errorf("nil input should yield no highlights")
	}
}

func TestFormatComment_SurfacesAgentSection(t *testing.T) {
	r := &PRReview{
		Verdict:        "request_changes",
		NewFindings:    1,
		AgentFindings:  2,
		Duration:       time.Second,
		AgentHighlights: []string{"**CRITICAL** `AGENT-CHAIN-001` — chain (package.json:5)"},
	}
	out := generateSummary(r)
	if !strings.Contains(out, "AI Agent Supply-Chain Security") {
		t.Errorf("expected the agent section header in the comment")
	}
	if !strings.Contains(out, "AGENT-CHAIN-001") {
		t.Errorf("expected the chain highlight in the comment")
	}
	if !strings.Contains(out, "never executed anything") {
		t.Errorf("expected the passive-analysis assurance in the comment")
	}
}
