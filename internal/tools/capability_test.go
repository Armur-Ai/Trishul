package internal

import "testing"

func TestRequiredBinary(t *testing.T) {
	if b, ok := RequiredBinary("semgrep"); !ok || b != "semgrep" {
		t.Errorf("RequiredBinary(semgrep) = %q,%v", b, ok)
	}
	if b, ok := RequiredBinary("govet"); !ok || b != "go" {
		t.Errorf("RequiredBinary(govet) = %q,%v, want go,true", b, ok)
	}
	if b, ok := RequiredBinary("clippy"); !ok || b != "cargo" {
		t.Errorf("RequiredBinary(clippy) = %q,%v, want cargo,true", b, ok)
	}
	if _, ok := RequiredBinary("not-a-real-tool"); ok {
		t.Errorf("unknown tool should not be mapped")
	}
}

func TestIsToolSkippable_UnknownNeverSkipped(t *testing.T) {
	// A tool we don't have a binary mapping for must never be reported skippable
	// (we don't skip on a guess).
	if IsToolSkippable("not-a-real-tool") {
		t.Errorf("unknown tool must not be skippable")
	}
}

func TestIsToolSkippable_ConsistentWithAvailability(t *testing.T) {
	// For a mapped tool, skippable iff its binary is absent.
	bin, _ := RequiredBinary("semgrep")
	if IsToolSkippable("semgrep") == ToolAvailable(bin) {
		t.Errorf("IsToolSkippable must be the negation of ToolAvailable(binary)")
	}
}
