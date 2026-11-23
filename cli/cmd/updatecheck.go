package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Opt-in update notifier (plan D0.6): at most once a day, never in CI, honoring
// TRISHUL_NO_UPDATE_CHECK. The network fetch of the latest version is injected so
// the cadence/gating logic is testable offline; a missing/failed fetch is silent.

const updateInterval = 24 * time.Hour

// updateCheckDisabled reports whether the update check must be skipped: explicitly
// disabled, or running in CI (where a notifier is noise).
func updateCheckDisabled(env func(string) string) bool {
	if env("TRISHUL_NO_UPDATE_CHECK") != "" {
		return true
	}
	for _, k := range []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE"} {
		if env(k) != "" {
			return true
		}
	}
	return false
}

// shouldCheck reports whether enough time has passed since the last check.
func shouldCheck(lastCheck, now time.Time) bool {
	return now.Sub(lastCheck) >= updateInterval
}

// stampPath is where the last-check timestamp lives.
func stampPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".cache", "trishul", "last-update-check")
}

func readStamp(path string) time.Time {
	b, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}
	}
	secs, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(secs, 0)
}

func writeStamp(path string, t time.Time) {
	if path == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	_ = os.WriteFile(path, []byte(strconv.FormatInt(t.Unix(), 10)), 0o644)
}

// newerVersion reports whether latest is a newer semver-ish tag than current.
// Both may carry a leading "v"; "dev"/empty current always yields false (we don't
// nag unreleased builds).
func newerVersion(current, latest string) bool {
	current = strings.TrimPrefix(strings.TrimSpace(current), "v")
	latest = strings.TrimPrefix(strings.TrimSpace(latest), "v")
	if current == "" || current == "dev" || latest == "" {
		return false
	}
	return compareSemver(latest, current) > 0
}

// compareSemver compares dotted numeric versions; non-numeric parts compare as 0.
func compareSemver(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(numericPrefix(as[i]))
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(numericPrefix(bs[i]))
		}
		if x != y {
			if x > y {
				return 1
			}
			return -1
		}
	}
	return 0
}

func numericPrefix(s string) string {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i]
}

// maybeNotifyUpdate runs the gated check and prints a one-line notice to w if a
// newer version is available. latestFn fetches the latest tag (injected/mockable);
// it is only called when the gate allows. Errors are swallowed (never noisy).
func maybeNotifyUpdate(current string, env func(string) string, now time.Time, latestFn func() (string, error), w io.Writer) {
	if updateCheckDisabled(env) {
		return
	}
	path := stampPath()
	if !shouldCheck(readStamp(path), now) {
		return
	}
	writeStamp(path, now) // stamp regardless, so a failing fetch doesn't retry all day
	if latestFn == nil {
		return
	}
	latest, err := latestFn()
	if err != nil {
		return
	}
	if newerVersion(current, latest) {
		fmt.Fprintf(w, "\n  A new Trishul is available: %s → %s. Update: https://github.com/Armur-Ai/Trishul/releases\n", current, latest)
	}
}

// latestReleaseTag fetches the latest Trishul release tag from GitHub (a version
// check only — no code or user data leaves the machine). Short timeout; any
// failure returns an error so the caller stays silent.
func latestReleaseTag() (string, error) {
	c := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/repos/Armur-Ai/Trishul/releases/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.TagName, nil
}
