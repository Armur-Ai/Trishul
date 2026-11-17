package sarif

import "testing"

func TestFromScanResults_IncludesVibeSecurity(t *testing.T) {
	results := map[string]interface{}{
		"vibe_security": []interface{}{
			map[string]interface{}{
				"check_id": "VIBE-WEBHOOK-001", "message": "Stripe webhook without signature verification",
				"severity": "HIGH", "path": "api/webhook.js", "line": 12,
			},
		},
	}
	run := FromScanResults(results, "test").Runs[0]
	var found *Result
	for i := range run.Results {
		if run.Results[i].RuleID == "VIBE-WEBHOOK-001" {
			found = &run.Results[i]
		}
	}
	if found == nil {
		t.Fatal("expected a VIBE-WEBHOOK-001 result in SARIF")
	}
	if len(found.Locations) == 0 || found.Locations[0].PhysicalLocation.Region == nil ||
		found.Locations[0].PhysicalLocation.Region.StartLine != 12 {
		t.Errorf("expected location at line 12")
	}
	if found.PartialFingerprints["trishul/v1"] == "" {
		t.Error("expected a partial fingerprint")
	}
	// A rule entry must be registered for the check id.
	var hasRule bool
	for _, r := range run.Tool.Driver.Rules {
		if r.ID == "VIBE-WEBHOOK-001" {
			hasRule = true
		}
	}
	if !hasRule {
		t.Error("expected a SARIF rule for VIBE-WEBHOOK-001")
	}
}
