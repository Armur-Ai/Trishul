package tui

import (
	"strings"
	"testing"
)

func TestSeverityRankOrdering(t *testing.T) {
	order := []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
	for i := 1; i < len(order); i++ {
		if SeverityRank(order[i]) <= SeverityRank(order[i-1]) {
			t.Fatalf("expected %s to outrank %s", order[i], order[i-1])
		}
	}
	// Case-insensitive and whitespace-tolerant.
	if SeverityRank(" critical ") != SeverityRank("CRITICAL") {
		t.Fatalf("severity rank should normalize case/whitespace")
	}
	// Unknown severities rank lowest.
	if SeverityRank("bogus") != 0 {
		t.Fatalf("unknown severity should rank 0")
	}
}

func TestNormalizeSeverityDefaults(t *testing.T) {
	if NormalizeSeverity("") != "INFO" {
		t.Fatalf("empty severity should default to INFO")
	}
	if NormalizeSeverity("high") != "HIGH" {
		t.Fatalf("expected normalized HIGH")
	}
}

func TestSeverityLabelFixedWidth(t *testing.T) {
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		if got := len(SeverityLabel(sev)); got != 4 {
			t.Fatalf("label for %s should be 4 chars, got %d (%q)", sev, got, SeverityLabel(sev))
		}
	}
}

func TestRedactNeverRevealsSecret(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	out := Redact(secret)
	if strings.Contains(out, "IOSFODNN7EXAMPLE") {
		t.Fatalf("redaction leaked the secret body: %q", out)
	}
	if out == secret {
		t.Fatalf("redaction returned the raw secret")
	}
	if !strings.Contains(out, "•") {
		t.Fatalf("redaction should contain mask characters: %q", out)
	}
	// Short secrets are fully masked (no prefix leak).
	if full := Redact("abc"); strings.ContainsAny(full, "abc") {
		t.Fatalf("short secret should be fully masked, got %q", full)
	}
	// Empty stays masked, never empty.
	if Redact("") == "" {
		t.Fatalf("empty secret should still render a masked placeholder")
	}
}

func TestCategoryLabelMapping(t *testing.T) {
	cases := map[string]string{
		"agent_security":   "Agent-Chain",
		"secret_detection": "Secrets",
		"sca":              "Dependencies",
		"infra_security":   "IaC",
		"security_issues":  "Security",
	}
	for in, want := range cases {
		if got := CategoryLabel(in); got != want {
			t.Fatalf("CategoryLabel(%q) = %q, want %q", in, got, want)
		}
	}
	// Unknown categories pass through unchanged.
	if CategoryLabel("custom_thing") != "custom_thing" {
		t.Fatalf("unknown category should pass through")
	}
}

func TestClampWidth(t *testing.T) {
	if clampWidth(0, 80, 100) != 80 {
		t.Fatalf("zero width should fall back")
	}
	if clampWidth(200, 80, 100) != 100 {
		t.Fatalf("over-max width should clamp")
	}
	if clampWidth(70, 80, 100) != 70 {
		t.Fatalf("in-range width should pass through")
	}
}
