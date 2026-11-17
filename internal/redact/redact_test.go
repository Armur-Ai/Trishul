package redact

import (
	"strings"
	"testing"
)

func TestMask_ShortSecretFullyMasked(t *testing.T) {
	for _, s := range []string{"", "a", "short", "elevenchars", "secret1"} {
		if got := Mask(s); got != "[REDACTED]" {
			t.Errorf("Mask(%q) = %q, want %q", s, got, "[REDACTED]")
		}
	}
}

func TestMask_LongSecretRevealsEdges(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	got := Mask(secret)
	if !strings.HasPrefix(got, "AKIA") {
		t.Errorf("Mask(%q) = %q, want prefix %q", secret, got, "AKIA")
	}
	if !strings.HasSuffix(got, "MPLE") {
		t.Errorf("Mask(%q) = %q, want suffix %q", secret, got, "MPLE")
	}
	if !strings.Contains(got, "...") {
		t.Errorf("Mask(%q) = %q, want it to contain ellipsis", secret, got)
	}
}

func TestMask_FullSecretNeverSubstringForLong(t *testing.T) {
	// 12 is the boundary; test at and above it.
	secrets := []string{
		"123456789012",             // exactly 12
		"AKIAIOSFODNN7EXAMPLE",     // 20
		strings.Repeat("x", 128),   // long, repeated chars (adversarial)
		"abcdefghijklmnopqrstuvwx", // 24 distinct-ish
	}
	for _, s := range secrets {
		got := Mask(s)
		if strings.Contains(got, s) {
			t.Errorf("Mask(%q) = %q leaks the full secret as a substring", s, got)
		}
	}
}

func TestMask_AtBoundary(t *testing.T) {
	eleven := "12345678901" // len 11 -> masked
	if got := Mask(eleven); got != "[REDACTED]" {
		t.Errorf("Mask(len 11) = %q, want %q", got, "[REDACTED]")
	}
	twelve := "123456789012" // len 12 -> revealed edges
	if got := Mask(twelve); got != "1234...9012" {
		t.Errorf("Mask(len 12) = %q, want %q", got, "1234...9012")
	}
}

func TestMask_Deterministic(t *testing.T) {
	s := "AKIAIOSFODNN7EXAMPLE"
	if Mask(s) != Mask(s) {
		t.Errorf("Mask is not deterministic for %q", s)
	}
}

func TestFingerprint_Stable(t *testing.T) {
	s := "AKIAIOSFODNN7EXAMPLE"
	want := Fingerprint(s)
	for i := 0; i < 5; i++ {
		if got := Fingerprint(s); got != want {
			t.Errorf("Fingerprint(%q) call %d = %q, want %q", s, i, got, want)
		}
	}
}

func TestFingerprint_LengthAndHex(t *testing.T) {
	got := Fingerprint("anything")
	if len(got) != 12 {
		t.Fatalf("Fingerprint length = %d, want 12", len(got))
	}
	for _, c := range got {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("Fingerprint %q contains non-hex char %q", got, c)
		}
	}
}

func TestFingerprint_Distinct(t *testing.T) {
	if Fingerprint("secret1") == Fingerprint("secret2") {
		t.Error("expected distinct fingerprints for distinct secrets")
	}
}

func TestFingerprint_KnownVector(t *testing.T) {
	// sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	if got := Fingerprint(""); got != "e3b0c44298fc" {
		t.Errorf("Fingerprint(\"\") = %q, want %q", got, "e3b0c44298fc")
	}
}

func TestFingerprint_EmptyNonEmpty(t *testing.T) {
	if Fingerprint("") == "" {
		t.Error("Fingerprint(\"\") must be non-empty")
	}
}
