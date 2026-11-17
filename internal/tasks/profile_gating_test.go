package tasks

import "testing"

func TestQualityProfileEnabled(t *testing.T) {
	t.Setenv("TRISHUL_PROFILE", "")
	if qualityProfileEnabled() {
		t.Error("quality tools must be off in the default profile")
	}
	for _, p := range []string{"quality", "all"} {
		t.Setenv("TRISHUL_PROFILE", p)
		if !qualityProfileEnabled() {
			t.Errorf("TRISHUL_PROFILE=%s must enable quality tools", p)
		}
	}
	t.Setenv("TRISHUL_PROFILE", "security")
	if qualityProfileEnabled() {
		t.Error("TRISHUL_PROFILE=security must not enable quality tools")
	}
}

// A quality tool must not run in the default security profile — the runner
// short-circuits it before invoking the tool, and that is not an error.
func TestWithTimeout_SkipsQualityToolInDefaultProfile(t *testing.T) {
	t.Setenv("TRISHUL_PROFILE", "")
	called := false
	res := withTimeout("golint", func() toolResult {
		called = true
		return toolResult{name: "golint"}
	})()
	if called {
		t.Error("quality tool must not run in the default security profile")
	}
	if res.err != nil {
		t.Errorf("profile omission must not be an error, got %v", res.err)
	}
}
