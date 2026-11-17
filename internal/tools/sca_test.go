package internal

import (
	"encoding/json"
	"testing"
)

func mustParseJSON(t *testing.T, raw string) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("test fixture is not valid JSON: %v", err)
	}
	return m
}

func TestFormatNpmAudit_NoVulnerabilities(t *testing.T) {
	raw := mustParseJSON(t, `{"metadata": {}}`)
	result := formatNpmAudit(raw)
	sca, ok := result["sca"].([]interface{})
	if !ok {
		t.Fatalf("expected sca slice, got %T", result["sca"])
	}
	if len(sca) != 0 {
		t.Errorf("expected 0 sca findings when no vulnerabilities key, got %d", len(sca))
	}
}

func TestFormatNpmAudit_WithVulnerabilities(t *testing.T) {
	raw := mustParseJSON(t, `{
		"vulnerabilities": {
			"lodash": {
				"severity": "high",
				"via": [
					{"title": "Prototype Pollution", "url": "https://npmjs.com/advisories/1065"}
				]
			}
		}
	}`)

	result := formatNpmAudit(raw)
	sca := result["sca"].([]interface{})
	if len(sca) != 1 {
		t.Fatalf("expected 1 sca finding, got %d", len(sca))
	}
	finding := sca[0].(map[string]interface{})
	if finding["severity"] != "HIGH" {
		t.Errorf("expected severity HIGH (uppercased), got %v", finding["severity"])
	}
	if finding["message"] != "lodash: Prototype Pollution" {
		t.Errorf("unexpected message, got %v", finding["message"])
	}
	if finding["cwe"] != "https://npmjs.com/advisories/1065" {
		t.Errorf("expected advisory url in cwe, got %v", finding["cwe"])
	}
}

func TestFormatNpmAudit_SeverityDefaultsMedium(t *testing.T) {
	raw := mustParseJSON(t, `{"vulnerabilities": {"pkg": {}}}`)
	result := formatNpmAudit(raw)
	sca := result["sca"].([]interface{})
	if len(sca) != 1 {
		t.Fatalf("expected 1 sca finding, got %d", len(sca))
	}
	finding := sca[0].(map[string]interface{})
	if finding["severity"] != "MEDIUM" {
		t.Errorf("expected default severity MEDIUM, got %v", finding["severity"])
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 80); got != "short" {
		t.Errorf("expected unchanged short string, got %q", got)
	}
	long := "0123456789"
	if got := truncate(long, 5); got != "01..." {
		t.Errorf("expected truncated string 01..., got %q", got)
	}
}
