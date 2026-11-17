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
