package internal

import "testing"

func TestIsQualityTool(t *testing.T) {
	for _, q := range []string{"golint", "gocyclo", "radon", "jscpd", "cargo-geiger", "vulture"} {
		if !IsQualityTool(q) {
			t.Errorf("%s should be classified as a quality tool", q)
		}
	}
	for _, s := range []string{"semgrep", "gosec", "bandit", "trivy", "checkov", "trufflehog"} {
		if IsQualityTool(s) {
			t.Errorf("%s is a security tool, not quality", s)
		}
	}
}
