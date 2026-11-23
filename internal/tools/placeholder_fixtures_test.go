package internal

import (
	"testing"

	"github.com/Armur-Ai/Trishul/internal/fixtures"
	utils "github.com/Armur-Ai/Trishul/pkg"
)

// TestPlaceholderFixtures runs the shared FP/TP regression harness (plan P0.2)
// over sanitized cases for each VIBE-PLACEHOLDER-001..006 rule. Every case under
// testdata/placeholder/fp/** must yield 0 findings (a precision guard) and every
// case under testdata/placeholder/tp/** must yield >= 1 (a recall guard). Cases
// are scanned through the real RunPlaceholderSecurity entrypoint.
func TestPlaceholderFixtures(t *testing.T) {
	fixtures.Walk(t, "testdata/placeholder", func(dir string) (int, error) {
		res, err := RunPlaceholderSecurity(dir)
		if err != nil {
			return 0, err
		}
		list, _ := res[utils.VIBE_SECURITY].([]interface{})
		return len(list), nil
	})
}
