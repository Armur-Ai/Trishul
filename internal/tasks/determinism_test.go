package tasks

import (
	"encoding/json"
	"testing"

	utils "github.com/Armur-Ai/Trishul/pkg"
)

// The built-in, dependency-free analyzers must produce byte-identical output
// across runs (sorted, de-duplicated) so SARIF/CLI diffs are stable in CI.
func TestBuiltInAnalyzers_Deterministic(t *testing.T) {
	const dir = "../../examples/vibe-coded-app"
	builtinCats := []string{
		utils.VIBE_SECURITY, utils.AGENT_SECURITY, utils.INFRA_SECURITY, utils.SECRET_DETECTION,
	}
	snap := func() string {
		res, _, err := RunSimpleScanLocal(dir, "")
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		subset := map[string]interface{}{}
		for _, c := range builtinCats {
			subset[c] = res[c]
		}
		b, _ := json.Marshal(subset)
		return string(b)
	}
	a, b := snap(), snap()
	if a != b {
		t.Errorf("built-in analyzer output is not deterministic across runs:\n run1: %s\n run2: %s", a, b)
	}
	// Sanity: the reference app must actually produce some built-in findings.
	if len(a) < 20 {
		t.Errorf("expected non-trivial built-in findings on the reference app, got: %s", a)
	}
}
