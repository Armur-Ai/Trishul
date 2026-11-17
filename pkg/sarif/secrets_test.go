package sarif

import (
	"strings"
	"testing"
)

func TestFromScanResults_IncludesRedactedSecrets(t *testing.T) {
	results := map[string]interface{}{
		"secret_detection": []interface{}{
			map[string]interface{}{
				"path":           "config.py",
				"line":           7,
				"message":        "Generic API Key",
				"severity":       "HIGH",
				"secret_preview": "AKIA...MPLE",
				"fingerprint":    "abc123def456",
			},
		},
	}
	log := FromScanResults(results, "test")
	run := log.Runs[0]

	var secretResult *Result
	for i := range run.Results {
		if run.Results[i].RuleID == "CWE-798" {
			secretResult = &run.Results[i]
		}
	}
	if secretResult == nil {
		t.Fatalf("expected a CWE-798 secret result in SARIF output")
	}
	if !strings.Contains(secretResult.Message.Text, "AKIA...MPLE") {
		t.Errorf("expected the redacted preview in the message, got %q", secretResult.Message.Text)
	}
	if secretResult.PartialFingerprints["trishul/v1"] == "" {
		t.Errorf("expected a partial fingerprint on the secret result")
	}
	if len(secretResult.Locations) == 0 || secretResult.Locations[0].PhysicalLocation.ArtifactLocation.URI != "config.py" {
		t.Errorf("expected a location of config.py")
	}
}
