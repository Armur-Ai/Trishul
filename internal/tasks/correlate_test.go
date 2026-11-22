package tasks

import (
	"testing"

	utils "github.com/Armur-Ai/Trishul/pkg"
)

func TestCorrelatedExploitabilityJoinsSCAAndExploitability(t *testing.T) {
	// SCA confirms CVE-2021-3129 present; exploitability says APP_DEBUG=true for it.
	out := map[string]interface{}{
		utils.SCA: []interface{}{
			map[string]interface{}{"check_id": "GHSA-xxxx", "message": "laravel ignition CVE-2021-3129 RCE"},
		},
	}
	newCatResult := map[string]interface{}{
		utils.EXPLOITABILITY: []interface{}{
			map[string]interface{}{
				"check_id": "EXPLOIT-LARAVEL-DEBUG-001", "cve": "CVE-2021-3129",
				"condition": "APP_DEBUG=true", "path": ".env", "line": 2, "severity": "HIGH",
			},
		},
	}
	got := correlatedExploitability(out, newCatResult)
	var hasCorrelated bool
	for _, item := range got {
		if m, ok := item.(map[string]interface{}); ok && m["check_id"] == "EXPLOIT-CORRELATED-001" {
			hasCorrelated = true
			if m["severity"] != "CRITICAL" {
				t.Errorf("correlated finding should be CRITICAL, got %v", m["severity"])
			}
		}
	}
	if !hasCorrelated {
		t.Fatalf("expected a LIVE-EXPLOITABLE correlated finding, got %d findings", len(got))
	}
	// The original exploitability finding must still be present (correlation adds, not replaces).
	if len(got) < 2 {
		t.Errorf("correlation should augment, not replace: got %d", len(got))
	}
}

func TestCorrelatedExploitabilityNoFalseJoin(t *testing.T) {
	out := map[string]interface{}{
		utils.SCA: []interface{}{map[string]interface{}{"message": "some other CVE-2000-1111"}},
	}
	newCatResult := map[string]interface{}{
		utils.EXPLOITABILITY: []interface{}{
			map[string]interface{}{"check_id": "EXPLOIT-FLASK-DEBUG-001", "cve": "", "path": "app.py"},
		},
	}
	for _, item := range correlatedExploitability(out, newCatResult) {
		if m, ok := item.(map[string]interface{}); ok && m["check_id"] == "EXPLOIT-CORRELATED-001" {
			t.Fatal("must not correlate when no shared CVE")
		}
	}
}
