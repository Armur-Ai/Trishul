package internal

import (
	"testing"
)

func TestParseGitleaksOutput_Empty(t *testing.T) {
	result, err := parseGitleaksOutput([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error for empty input: %v", err)
	}
	secrets, ok := result["secret_detection"].([]interface{})
	if !ok {
		t.Fatalf("expected secret_detection slice, got %T", result["secret_detection"])
	}
	if len(secrets) != 0 {
		t.Errorf("expected 0 secrets for empty input, got %d", len(secrets))
	}
}

func TestParseGitleaksOutput_InvalidJSON(t *testing.T) {
	result, err := parseGitleaksOutput([]byte("{not valid json"))
	if err != nil {
		t.Fatalf("expected no error (graceful) for invalid JSON, got %v", err)
	}
	secrets := result["secret_detection"].([]interface{})
	if len(secrets) != 0 {
		t.Errorf("expected 0 secrets for invalid JSON, got %d", len(secrets))
	}
}

func TestParseGitleaksOutput_WithFindings(t *testing.T) {
	input := `[
		{
			"RuleID": "aws-access-token",
			"Description": "AWS Access Token",
			"File": "config/secrets.yml",
			"StartLine": 12,
			"Commit": "abc123",
			"Author": "dev",
			"Date": "2023-01-01T00:00:00Z"
		},
		{
			"RuleID": "generic-api-key",
			"Description": "Generic API Key",
			"File": ".env",
			"StartLine": 3
		}
	]`

	result, err := parseGitleaksOutput([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	secrets := result["secret_detection"].([]interface{})
	if len(secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(secrets))
	}

	first := secrets[0].(map[string]interface{})
	if first["severity"] != "CRITICAL" {
		t.Errorf("expected severity CRITICAL, got %v", first["severity"])
	}
	if first["line"] != 12 {
		t.Errorf("expected line 12, got %v", first["line"])
	}
	if first["rule_id"] != "aws-access-token" {
		t.Errorf("expected rule_id aws-access-token, got %v", first["rule_id"])
	}
	if first["commit"] != "abc123" {
		t.Errorf("expected commit metadata to be present, got %v", first["commit"])
	}

	second := secrets[1].(map[string]interface{})
	if _, hasCommit := second["commit"]; hasCommit {
		t.Errorf("expected no commit field when commit empty, got %v", second["commit"])
	}
}
