package suite

import (
	"testing"

	"github.com/Armur-Ai/Trishul/internal/models"
	contracts "github.com/Armur-Ai/armur-contracts"
)

func TestEmitSeparatesByType(t *testing.T) {
	r := models.ScanResult{
		TaskID: "task-1",
		Meta:   models.ScanMeta{Language: "go", ToolsRun: []string{"gosec"}, FileCount: 12},
		Findings: []models.Finding{
			{ID: "a", Tool: "gosec", Source: "sast", Category: "security_issues", Severity: models.SeverityHigh, CWE: "CWE-89", File: "x.go", Line: 10},
			{ID: "b", Tool: "gitleaks", Source: "secrets", Severity: models.SeverityHigh, File: ".env", Line: 1},
			{ID: "c", Tool: "osv", Source: "sca", Severity: models.SeverityMedium, File: "go.mod"},
			{ID: "d", Tool: "linter", Source: "quality", Category: "complex_functions", Severity: models.SeverityLow, File: "y.go"},
		},
	}
	b := EmitCodeAnalysisBundle(r, "v-test")

	if b.RunID != "task-1" {
		t.Fatalf("run id = %q", b.RunID)
	}
	if len(b.SourceClaims) != 2 { // security_issue + dependency_advisory
		t.Fatalf("source claims = %d, want 2", len(b.SourceClaims))
	}
	if len(b.Secrets) != 1 {
		t.Fatalf("secrets = %d, want 1", len(b.Secrets))
	}
	if len(b.Issues) != 1 || b.Issues[0].Kind != contracts.IssueMaintainability {
		t.Fatalf("quality issue mapping wrong: %+v", b.Issues)
	}
	// honesty: an unconfirmed SAST claim is "declared", never confirmed.
	for _, c := range b.SourceClaims {
		if c.Kind == contracts.ClaimSourceWeakness && c.Status != contracts.StatusDeclared {
			t.Fatalf("unconfirmed SAST claim should be declared, got %q", c.Status)
		}
	}
}

func TestConfirmedRuntimeStatus(t *testing.T) {
	r := models.ScanResult{
		TaskID: "t2",
		Findings: []models.Finding{
			{ID: "e", Tool: "swarm", Source: "exploit", Category: "security_issues", Confirmed: true, Severity: models.SeverityCritical, File: "h.go"},
		},
	}
	b := EmitCodeAnalysisBundle(r, "v")
	if len(b.SourceClaims) != 1 || b.SourceClaims[0].Status != contracts.StatusRuntimeConfirmed {
		t.Fatalf("confirmed exploit should be runtime_confirmed: %+v", b.SourceClaims)
	}
}
