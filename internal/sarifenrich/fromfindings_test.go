package sarifenrich

import (
	"encoding/json"
	"testing"

	"github.com/Armur-Ai/Trishul/internal/findings"
)

func TestFromFindings(t *testing.T) {
	fs := []findings.Finding{
		findings.New(findings.Finding{
			RuleID: "AGENT-EXEC-002", Analyzer: "agentsec", Title: "hook rce",
			Message: "curl | sh", Severity: findings.SeverityHigh, Confidence: 0.9,
			Location: findings.Location{Path: ".claude/settings.json", StartLine: 12},
		}),
		findings.New(findings.Finding{
			RuleID: "VIBE-AUTHZ-001", Analyzer: "vibe", Severity: findings.SeverityMedium,
			Confidence: 0.5, Location: findings.Location{Path: "api.ts", StartLine: 3},
		}),
	}
	log := FromFindings(fs, testCatalog(t), map[string]float64{"AGENT-EXEC-002": 0.83}, "trishul", "9.9.9", "https://armur.ai")

	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("bad log shape: %+v", log)
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "trishul" {
		t.Errorf("driver name=%q", run.Tool.Driver.Name)
	}
	if len(run.Results) != 2 {
		t.Fatalf("want 2 results, got %d", len(run.Results))
	}
	r0 := run.Results[0]
	if r0.Level != "error" {
		t.Errorf("high severity should be error level, got %q", r0.Level)
	}
	if r0.Locations[0].PhysicalLocation.Region.StartLine != 12 {
		t.Errorf("region line wrong: %+v", r0.Locations[0].PhysicalLocation.Region)
	}
	if r0.PartialFingerprints["trishulFingerprintV2"] == "" {
		t.Error("fingerprint not carried to SARIF")
	}
	// enrichment ran: the rule entry exists and has security-severity.
	var hasRule bool
	for _, rule := range run.Tool.Driver.Rules {
		if rule.ID == "AGENT-EXEC-002" && rule.Properties["security-severity"] == "8.0" {
			hasRule = true
		}
	}
	if !hasRule {
		t.Error("rules[] not enriched for AGENT-EXEC-002")
	}

	// whole thing marshals to valid JSON
	if _, err := json.Marshal(log); err != nil {
		t.Fatalf("marshal: %v", err)
	}
}

func TestLevelFor(t *testing.T) {
	if levelFor(findings.SeverityCritical) != "error" || levelFor(findings.SeverityLow) != "note" {
		t.Error("level mapping wrong")
	}
}
