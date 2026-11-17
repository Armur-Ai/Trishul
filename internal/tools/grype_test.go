package internal

import (
	"testing"
)

func TestParseGrypeOutput_Empty(t *testing.T) {
	result, err := parseGrypeOutput([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error for empty input: %v", err)
	}
	sca, ok := result["sca"].([]interface{})
	if !ok {
		t.Fatalf("expected sca slice, got %T", result["sca"])
	}
	if len(sca) != 0 {
		t.Errorf("expected 0 sca findings for empty input, got %d", len(sca))
	}
}

func TestParseGrypeOutput_InvalidJSON(t *testing.T) {
	result, err := parseGrypeOutput([]byte("{bad json"))
	if err != nil {
		t.Fatalf("expected graceful handling, got %v", err)
	}
	if len(result["sca"].([]interface{})) != 0 {
		t.Errorf("expected 0 findings for invalid JSON")
	}
}

func TestParseGrypeOutput_WithMatches(t *testing.T) {
	input := `{
		"matches": [
			{
				"vulnerability": {
					"id": "CVE-2022-1234",
					"severity": "High",
					"description": "A serious vulnerability",
					"fix": {"versions": ["1.2.3"]}
				},
				"artifact": {
					"name": "libfoo",
					"version": "1.2.0",
					"type": "deb"
				}
			}
		]
	}`

	result, err := parseGrypeOutput([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sca := result["sca"].([]interface{})
	if len(sca) != 1 {
		t.Fatalf("expected 1 sca finding, got %d", len(sca))
	}
	finding := sca[0].(map[string]interface{})
	if finding["severity"] != "HIGH" {
		t.Errorf("expected severity HIGH (uppercased), got %v", finding["severity"])
	}
	if finding["path"] != "libfoo@1.2.0" {
		t.Errorf("expected path libfoo@1.2.0, got %v", finding["path"])
	}
	if finding["cwe"] != "CVE-2022-1234" {
		t.Errorf("expected cwe CVE-2022-1234, got %v", finding["cwe"])
	}
}

func TestParseTrivyImageOutput_WithVulns(t *testing.T) {
	input := `{
		"Results": [
			{
				"Target": "alpine:3.14 (alpine 3.14.0)",
				"Vulnerabilities": [
					{
						"VulnerabilityID": "CVE-2021-9999",
						"PkgName": "openssl",
						"InstalledVersion": "1.1.1k",
						"FixedVersion": "1.1.1l",
						"Severity": "CRITICAL",
						"Title": "OpenSSL flaw"
					}
				]
			}
		]
	}`

	result, err := parseTrivyImageOutput([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sca := result["sca"].([]interface{})
	if len(sca) != 1 {
		t.Fatalf("expected 1 sca finding, got %d", len(sca))
	}
	finding := sca[0].(map[string]interface{})
	if finding["severity"] != "CRITICAL" {
		t.Errorf("expected severity CRITICAL, got %v", finding["severity"])
	}
}

func TestParseTrivyImageOutput_Empty(t *testing.T) {
	result, err := parseTrivyImageOutput([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error for empty input: %v", err)
	}
	if len(result["sca"].([]interface{})) != 0 {
		t.Errorf("expected 0 findings for empty input")
	}
}
