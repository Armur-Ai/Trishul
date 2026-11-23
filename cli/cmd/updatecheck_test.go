package cmd

import (
	"strings"
	"testing"
	"time"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestUpdateCheckDisabled(t *testing.T) {
	if !updateCheckDisabled(envMap(map[string]string{"TRISHUL_NO_UPDATE_CHECK": "1"})) {
		t.Error("explicit opt-out should disable")
	}
	if !updateCheckDisabled(envMap(map[string]string{"CI": "true"})) {
		t.Error("CI should disable")
	}
	if !updateCheckDisabled(envMap(map[string]string{"GITHUB_ACTIONS": "true"})) {
		t.Error("GitHub Actions should disable")
	}
	if updateCheckDisabled(envMap(map[string]string{})) {
		t.Error("clean env should allow")
	}
}

func TestShouldCheck(t *testing.T) {
	now := time.Now()
	if shouldCheck(now.Add(-time.Hour), now) {
		t.Error("1h ago should not trigger")
	}
	if !shouldCheck(now.Add(-25*time.Hour), now) {
		t.Error("25h ago should trigger")
	}
	if !shouldCheck(time.Time{}, now) {
		t.Error("never-checked should trigger")
	}
}

func TestNewerVersion(t *testing.T) {
	cases := []struct {
		cur, latest string
		want        bool
	}{
		{"v0.2.0", "v0.3.0", true},
		{"0.2.0", "0.2.1", true},
		{"v0.3.0", "v0.3.0", false},
		{"v0.3.0", "v0.2.9", false},
		{"dev", "v9.9.9", false}, // don't nag dev builds
		{"", "v1.0.0", false},
	}
	for _, c := range cases {
		if got := newerVersion(c.cur, c.latest); got != c.want {
			t.Errorf("newerVersion(%q,%q)=%v want %v", c.cur, c.latest, got, c.want)
		}
	}
}

func TestMaybeNotifyUpdate_GatesAndNotifies(t *testing.T) {
	// disabled env -> latestFn never called, no output
	called := false
	var b strings.Builder
	maybeNotifyUpdate("v0.2.0", envMap(map[string]string{"CI": "1"}), time.Now(),
		func() (string, error) { called = true; return "v9.9.9", nil }, &b)
	if called || b.Len() != 0 {
		t.Error("disabled env must not fetch or print")
	}

	// allowed + newer -> prints (use a never-checked stamp by pointing HOME at temp)
	t.Setenv("HOME", t.TempDir())
	var b2 strings.Builder
	maybeNotifyUpdate("v0.2.0", envMap(map[string]string{}), time.Now(),
		func() (string, error) { return "v0.3.0", nil }, &b2)
	if !strings.Contains(b2.String(), "new Trishul is available") {
		t.Errorf("expected update notice, got %q", b2.String())
	}
}
