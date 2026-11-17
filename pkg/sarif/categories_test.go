package sarif

import (
	"strings"
	"testing"
)

// findByRule returns the first result with the given rule id, or nil.
func findByRule(run Run, ruleID string) *Result {
	for i := range run.Results {
		if run.Results[i].RuleID == ruleID {
			return &run.Results[i]
		}
	}
	return nil
}

// TestFromScanResults_IncludesSCA uses the real reformatted "sca" shape
// (grouped by manifest path, with the osv-scanner issue fields) and proves
// dependency findings reach the SARIF output with a location and fingerprint.
func TestFromScanResults_IncludesSCA(t *testing.T) {
	results := map[string]interface{}{
		"sca": []interface{}{
			map[string]interface{}{
				"path": "requirements.txt",
				"issues": []interface{}{
					map[string]interface{}{
						"path":     "requirements.txt",
						"package":  "flask",
						"version":  "0.12",
						"check_id": "CVE-2019-1010083",
						"message":  "Denial of Service in Flask",
						"severity": "HIGH",
					},
				},
			},
		},
	}

	run := FromScanResults(results, "test").Runs[0]
	r := findByRule(run, "CVE-2019-1010083")
	if r == nil {
		t.Fatalf("expected a CVE-2019-1010083 SCA result in SARIF output")
	}
	if r.Level != "error" {
		t.Errorf("expected level error for HIGH severity, got %q", r.Level)
	}
	if !strings.Contains(r.Message.Text, "flask@0.12") {
		t.Errorf("expected package@version in message, got %q", r.Message.Text)
	}
	if r.PartialFingerprints["trishul/v1"] == "" {
		t.Errorf("expected a partial fingerprint on the SCA result")
	}
	if len(r.Locations) == 0 || r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "requirements.txt" {
		t.Errorf("expected a location of requirements.txt")
	}
	// The advisory id must register a rule.
	if findRule(run, "CVE-2019-1010083") == nil {
		t.Errorf("expected a registered rule for CVE-2019-1010083")
	}
}

// TestFromScanResults_SCAFallbackRule proves a dependency finding with no
// advisory id still surfaces under a stable DEPENDENCY rule.
func TestFromScanResults_SCAFallbackRule(t *testing.T) {
	results := map[string]interface{}{
		"sca": []interface{}{
			map[string]interface{}{
				"path": "go.mod",
				"issues": []interface{}{
					map[string]interface{}{
						"path":     "go.mod",
						"package":  "somepkg",
						"version":  "1.2.3",
						"message":  "Unspecified vulnerability",
						"severity": "MEDIUM",
					},
				},
			},
		},
	}

	run := FromScanResults(results, "test").Runs[0]
	r := findByRule(run, "DEPENDENCY")
	if r == nil {
		t.Fatalf("expected a DEPENDENCY fallback result")
	}
	if r.PartialFingerprints["trishul/v1"] == "" {
		t.Errorf("expected a partial fingerprint on the DEPENDENCY result")
	}
	if !strings.Contains(r.Message.Text, "somepkg@1.2.3") {
		t.Errorf("expected package@version in message, got %q", r.Message.Text)
	}
}

// TestFromScanResults_SCAListSeverity proves list-valued severities (as
// osv-scanner can emit) are tolerated.
func TestFromScanResults_SCAListSeverity(t *testing.T) {
	results := map[string]interface{}{
		"sca": []interface{}{
			map[string]interface{}{
				"path":     "package-lock.json",
				"package":  "lodash",
				"version":  "4.17.4",
				"check_id": "GHSA-jf85-cpcp-j695",
				"message":  "Prototype pollution",
				"severity": []interface{}{"CRITICAL"},
			},
		},
	}

	run := FromScanResults(results, "test").Runs[0]
	r := findByRule(run, "GHSA-jf85-cpcp-j695")
	if r == nil {
		t.Fatalf("expected a GHSA SCA result (raw/flat shape)")
	}
	if r.Level != "error" {
		t.Errorf("expected level error for CRITICAL severity, got %q", r.Level)
	}
}

// TestFromScanResults_IncludesIaC uses the real reformatted "infra_security"
// shape (grouped by message, with the checkov issue fields) and proves IaC
// findings reach the SARIF output with a parsed start line and fingerprint.
func TestFromScanResults_IncludesIaC(t *testing.T) {
	results := map[string]interface{}{
		"infra_security": []interface{}{
			map[string]interface{}{
				"message": "Ensure the S3 bucket has access logging enabled",
				"issues": []interface{}{
					map[string]interface{}{
						"path":            "main.tf",
						"check_id":        "CKV_AWS_18",
						"severity":        "LOW",
						"message":         "Ensure the S3 bucket has access logging enabled",
						"file_line_range": "12:20",
					},
				},
			},
		},
	}

	run := FromScanResults(results, "test").Runs[0]
	r := findByRule(run, "CKV_AWS_18")
	if r == nil {
		t.Fatalf("expected a CKV_AWS_18 IaC result in SARIF output")
	}
	if r.PartialFingerprints["trishul/v1"] == "" {
		t.Errorf("expected a partial fingerprint on the IaC result")
	}
	if len(r.Locations) == 0 || r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "main.tf" {
		t.Fatalf("expected a location of main.tf")
	}
	region := r.Locations[0].PhysicalLocation.Region
	if region == nil || region.StartLine != 12 {
		t.Errorf("expected start line 12 parsed from file_line_range, got %+v", region)
	}
	if findRule(run, "CKV_AWS_18") == nil {
		t.Errorf("expected a registered rule for CKV_AWS_18")
	}
}

// TestFromScanResults_IaCFallbackRule proves an infra finding with no check id
// and no CWE still surfaces under a stable IAC rule.
func TestFromScanResults_IaCFallbackRule(t *testing.T) {
	results := map[string]interface{}{
		"infra_security": []interface{}{
			map[string]interface{}{
				"path":     "deploy.yaml",
				"severity": "MEDIUM",
				"message":  "Privileged container",
			},
		},
	}

	run := FromScanResults(results, "test").Runs[0]
	r := findByRule(run, "IAC")
	if r == nil {
		t.Fatalf("expected an IAC fallback result (raw/flat shape)")
	}
	if r.PartialFingerprints["trishul/v1"] == "" {
		t.Errorf("expected a partial fingerprint on the IAC result")
	}
	if len(r.Locations) == 0 || r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "deploy.yaml" {
		t.Errorf("expected a location of deploy.yaml")
	}
}

// TestFromScanResults_SecurityIssuesStableFallback proves CWE-less security
// findings no longer collapse onto a single UNKNOWN rule: two distinct findings
// in an "unknown" CWE group get two distinct, stable rule ids, each
// fingerprinted.
func TestFromScanResults_SecurityIssuesStableFallback(t *testing.T) {
	results := map[string]interface{}{
		"security_issues": []interface{}{
			map[string]interface{}{
				"cwe": "unknown",
				"files": []interface{}{
					map[string]interface{}{
						"path": "a.go",
						"issues": []interface{}{
							map[string]interface{}{"check_id": "rule.one", "message": "first issue", "severity": "HIGH"},
							map[string]interface{}{"check_id": "rule.two", "message": "second issue", "severity": "HIGH"},
						},
					},
				},
			},
		},
	}

	run := FromScanResults(results, "test").Runs[0]
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(run.Results))
	}
	if run.Results[0].RuleID == run.Results[1].RuleID {
		t.Errorf("expected distinct stable rule ids, both were %q", run.Results[0].RuleID)
	}
	for _, r := range run.Results {
		if r.RuleID == "UNKNOWN" || r.RuleID == "unknown" {
			t.Errorf("CWE-less finding collapsed onto %q", r.RuleID)
		}
		if !strings.HasPrefix(r.RuleID, "ARMUR-") {
			t.Errorf("expected ARMUR- prefixed stable id, got %q", r.RuleID)
		}
		if r.PartialFingerprints["trishul/v1"] == "" {
			t.Errorf("expected a partial fingerprint on %q", r.RuleID)
		}
	}
}

// findRule returns the registered rule with the given id, or nil.
func findRule(run Run, id string) *Rule {
	for i := range run.Tool.Driver.Rules {
		if run.Tool.Driver.Rules[i].ID == id {
			return &run.Tool.Driver.Rules[i]
		}
	}
	return nil
}
