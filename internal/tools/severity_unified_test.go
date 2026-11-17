package internal

import (
	"testing"

	"github.com/Armur-Ai/Trishul/internal/models"
)

// The generic (non-tool-specific) severity path must be exactly the canonical
// mapper in models — no divergent second copy.
func TestNormalizeSeverity_GenericDelegates(t *testing.T) {
	cases := []string{"CRITICAL", "high", "error", "severe", "medium", "warning",
		"moderate", "low", "minor", "info", "note", "style", "totally-unknown", ""}
	for _, raw := range cases {
		// "gosec" has no tool-specific case, so it exercises the generic path.
		got := NormalizeSeverity("gosec", raw)
		want := models.NormalizeSeverityString(raw)
		if got != want {
			t.Errorf("NormalizeSeverity(gosec, %q) = %v, canonical = %v", raw, got, want)
		}
	}
}
