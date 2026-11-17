package internal

import (
	"testing"
)

func TestParseTerrascanOutput_Empty(t *testing.T) {
	result, err := parseTerrascanOutput([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error for empty input: %v", err)
	}
	infra, ok := result["infra_security"].([]interface{})
	if !ok {
		t.Fatalf("expected infra_security slice, got %T", result["infra_security"])
	}
	if len(infra) != 0 {
		t.Errorf("expected 0 infra findings for empty input, got %d", len(infra))
	}
}

func TestParseTerrascanOutput_InvalidJSON(t *testing.T) {
	result, err := parseTerrascanOutput([]byte("{nope"))
	if err != nil {
		t.Fatalf("expected graceful handling, got %v", err)
	}
	if len(result["infra_security"].([]interface{})) != 0 {
		t.Errorf("expected 0 findings for invalid JSON")
	}
}

func TestParseTerrascanOutput_WithViolations(t *testing.T) {
	input := `{
		"results": {
			"violations": [
				{
					"rule_name": "s3EnforceUserACL",
					"description": "S3 bucket has public ACL",
					"rule_id": "AC_AWS_0001",
					"severity": "HIGH",
					"category": "S3",
					"file": "main.tf",
					"line": 15
				},
				{
					"rule_name": "unknownSevRule",
					"description": "desc",
					"rule_id": "AC_AWS_0002",
					"severity": "weird",
					"category": "IAM",
					"file": "iam.tf",
					"line": 2
				}
			]
		}
	}`

	result, err := parseTerrascanOutput([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	infra := result["infra_security"].([]interface{})
	if len(infra) != 2 {
		t.Fatalf("expected 2 infra findings, got %d", len(infra))
	}

	first := infra[0].(map[string]interface{})
	if first["severity"] != "HIGH" {
		t.Errorf("expected severity HIGH, got %v", first["severity"])
	}
	if first["rule_id"] != "AC_AWS_0001" {
		t.Errorf("expected rule_id AC_AWS_0001, got %v", first["rule_id"])
	}
	if first["path"] != "main.tf" {
		t.Errorf("expected path main.tf, got %v", first["path"])
	}

	second := infra[1].(map[string]interface{})
	if second["severity"] != "MEDIUM" {
		t.Errorf("expected unknown severity to map to MEDIUM, got %v", second["severity"])
	}
}

func TestMapTerrascanSeverity(t *testing.T) {
	cases := map[string]string{
		"HIGH":    "HIGH",
		"MEDIUM":  "MEDIUM",
		"LOW":     "LOW",
		"":        "MEDIUM",
		"UNKNOWN": "MEDIUM",
	}
	for in, want := range cases {
		if got := mapTerrascanSeverity(in); got != want {
			t.Errorf("mapTerrascanSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}
