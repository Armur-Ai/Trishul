package internal

import (
	"testing"
)

func TestParseGovulncheckOutput_Empty(t *testing.T) {
	result, err := parseGovulncheckOutput([]byte(""))
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

func TestParseGovulncheckOutput_InvalidJSON(t *testing.T) {
	result, err := parseGovulncheckOutput([]byte("this is not json"))
	if err != nil {
		t.Fatalf("expected graceful handling of invalid JSON, got %v", err)
	}
	sca := result["sca"].([]interface{})
	if len(sca) != 0 {
		t.Errorf("expected 0 sca findings for invalid JSON, got %d", len(sca))
	}
}

func TestParseGovulncheckOutput_WithFindings(t *testing.T) {
	// govulncheck emits newline-delimited JSON messages.
	reachable := `{"finding":{"osv":"GO-2023-0001","trace":[{"module":"example.com/pkg","function":"Bad"}]}}`
	notReachable := `{"finding":{"osv":"GO-2023-0002"}}`
	other := `{"config":{"protocol_version":"v1.0.0"}}`
	input := other + "\n" + reachable + "\n" + notReachable + "\n"

	result, err := parseGovulncheckOutput([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sca := result["sca"].([]interface{})
	if len(sca) != 2 {
		t.Fatalf("expected 2 sca findings, got %d", len(sca))
	}

	first := sca[0].(map[string]interface{})
	if first["severity"] != "CRITICAL" {
		t.Errorf("expected CRITICAL for reachable vuln, got %v", first["severity"])
	}
	if first["cwe"] != "GO-2023-0001" {
		t.Errorf("expected osv GO-2023-0001, got %v", first["cwe"])
	}

	second := sca[1].(map[string]interface{})
	if second["severity"] != "HIGH" {
		t.Errorf("expected HIGH for unreachable vuln, got %v", second["severity"])
	}
}
