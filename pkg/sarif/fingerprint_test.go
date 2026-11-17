package sarif

import "testing"

func TestFingerprint_DeterministicAndLineInsensitive(t *testing.T) {
	a := fingerprint("CWE-89", "app/db.go", "SQL injection")
	b := fingerprint("CWE-89", "app/db.go", "SQL injection")
	if a != b {
		t.Errorf("fingerprint must be deterministic: %q != %q", a, b)
	}
	if fingerprint("CWE-89", "app/db.go", "SQL injection") == fingerprint("CWE-79", "app/db.go", "SQL injection") {
		t.Errorf("different rules must yield different fingerprints")
	}
	if len(a) != 16 {
		t.Errorf("fingerprint length = %d, want 16", len(a))
	}
}

func TestFromScanResults_FingerprintsAndRuleOrder(t *testing.T) {
	// Two CWE rules, provided out of lexical order, each with one issue.
	results := map[string]interface{}{
		"security_issues": []interface{}{
			map[string]interface{}{
				"cwe": "CWE-89",
				"files": []interface{}{
					map[string]interface{}{
						"path": "app/db.go",
						"issues": []interface{}{
							map[string]interface{}{"line": 10, "message": "SQLi", "severity": "HIGH"},
						},
					},
				},
			},
			map[string]interface{}{
				"cwe": "CWE-79",
				"files": []interface{}{
					map[string]interface{}{
						"path": "app/web.go",
						"issues": []interface{}{
							map[string]interface{}{"line": 5, "message": "XSS", "severity": "MEDIUM"},
						},
					},
				},
			},
		},
	}

	log := FromScanResults(results, "test")
	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}
	run := log.Runs[0]

	// Every result carries a stable partial fingerprint.
	for _, r := range run.Results {
		if r.PartialFingerprints["trishul/v1"] == "" {
			t.Errorf("result for %s missing partialFingerprints", r.RuleID)
		}
	}

	// Rules are emitted in deterministic (sorted) order regardless of input order.
	rules := run.Tool.Driver.Rules
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	if rules[0].ID > rules[1].ID {
		t.Errorf("rules not sorted: %q then %q", rules[0].ID, rules[1].ID)
	}
}
