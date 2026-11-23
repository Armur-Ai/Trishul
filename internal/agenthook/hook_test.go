package agenthook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stubScan is a deterministic ScanFunc for tests: it reads the single file in
// dir and emits a finding for each FINDING_HIGH / FINDING_MED marker line.
func stubScan(dir string) ([]Finding, error) {
	var fs []Finding
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		b, _ := os.ReadFile(p)
		for i, line := range strings.Split(string(b), "\n") {
			switch {
			case strings.Contains(line, "FINDING_HIGH"):
				fs = append(fs, Finding{RuleID: "TEST-HIGH", Severity: "high", Path: rel, Line: i + 1, Message: "high issue", Fix: "fix it"})
			case strings.Contains(line, "FINDING_MED"):
				fs = append(fs, Finding{RuleID: "TEST-MED", Severity: "medium", Path: rel, Line: i + 1, Message: "med issue", Fix: "fix it"})
			}
		}
		return nil
	})
	return fs, err
}

// stubBash returns a single HIGH finding when the command contains "DANGER".
func stubBash(command, _ string) []Finding {
	if strings.Contains(command, "DANGER") {
		return []Finding{{RuleID: "TEST-BASH", Severity: "high", Message: "dangerous command", Fix: "don't"}}
	}
	return nil
}

type hookCall struct {
	t       *testing.T
	opts    Options
	session string
	cwd     string
}

func newHookCall(t *testing.T) *hookCall {
	t.Helper()
	tmp := t.TempDir()
	ws := t.TempDir()
	return &hookCall{
		t:       t,
		opts:    Options{Scanner: stubScan, BashScanner: stubBash, TmpRoot: tmp},
		session: "sess-1",
		cwd:     ws,
	}
}

// writeFile writes content into the workspace and returns the relative path.
func (h *hookCall) writeFile(rel, content string) string {
	h.t.Helper()
	abs := filepath.Join(h.cwd, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
	return rel
}

func (h *hookCall) run(payload map[string]any) (int, string, string) {
	h.t.Helper()
	if _, ok := payload["session_id"]; !ok {
		payload["session_id"] = h.session
	}
	if _, ok := payload["cwd"]; !ok {
		payload["cwd"] = h.cwd
	}
	data, err := json.Marshal(payload)
	if err != nil {
		h.t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := Run(bytes.NewReader(data), &out, &errb, h.opts)
	return code, out.String(), errb.String()
}

func postWrite(rel string) map[string]any {
	return map[string]any{
		"hook_event_name": "PostToolUse",
		"tool_name":       "Write",
		"tool_input":      map[string]any{"file_path": rel, "content": ""},
	}
}

func TestPostToolUse(t *testing.T) {
	t.Run("new high finding blocks with golden stderr", func(t *testing.T) {
		h := newHookCall(t)
		rel := h.writeFile("app.py", "x = 1  # FINDING_HIGH\n")
		code, _, stderr := h.run(postWrite(rel))
		if code != 2 {
			t.Fatalf("exit code = %d, want 2", code)
		}
		want := `Trishul blocked this edit: 1 new issue at or above "high".

  [HIGH] TEST-HIGH  app.py:1
    why: high issue
    fix: fix it

Resolve the issue, or add a reviewed inline suppression (e.g. trishul-ignore[RULE-ID]: reason).
`
		if stderr != want {
			t.Fatalf("stderr mismatch\n--- got ---\n%s\n--- want ---\n%s", stderr, want)
		}
	})

	t.Run("clean edit exits 0 silently", func(t *testing.T) {
		h := newHookCall(t)
		rel := h.writeFile("app.py", "x = 1  # all good\n")
		code, out, stderr := h.run(postWrite(rel))
		if code != 0 || out != "" || stderr != "" {
			t.Fatalf("code=%d out=%q stderr=%q, want 0/empty/empty", code, out, stderr)
		}
	})

	t.Run("finding below block_on is ignored", func(t *testing.T) {
		h := newHookCall(t)
		rel := h.writeFile("app.py", "x = 1  # FINDING_MED\n")
		code, _, stderr := h.run(postWrite(rel))
		if code != 0 || stderr != "" {
			t.Fatalf("code=%d stderr=%q, want 0/empty (medium < high)", code, stderr)
		}
	})

	t.Run("inline suppression respected", func(t *testing.T) {
		h := newHookCall(t)
		rel := h.writeFile("app.py", "# trishul-ignore[TEST-HIGH]: accepted for test\nx = 1  # FINDING_HIGH\n")
		code, _, stderr := h.run(postWrite(rel))
		if code != 0 || stderr != "" {
			t.Fatalf("code=%d stderr=%q, want suppressed (0/empty)", code, stderr)
		}
	})

	t.Run("non-code-like file skipped", func(t *testing.T) {
		h := newHookCall(t)
		// A lockfile is classified as generated → not code-like → never scanned.
		rel := h.writeFile("go.sum", "x = 1  # FINDING_HIGH\n")
		code, _, stderr := h.run(postWrite(rel))
		if code != 0 || stderr != "" {
			t.Fatalf("code=%d stderr=%q, want skipped (0/empty)", code, stderr)
		}
	})

	t.Run("rules_exclude drops the finding", func(t *testing.T) {
		h := newHookCall(t)
		if err := os.WriteFile(filepath.Join(h.cwd, ".trishul.yml"),
			[]byte("agent_hook:\n  rules_exclude: [TEST-HIGH]\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		rel := h.writeFile("app.py", "x = 1  # FINDING_HIGH\n")
		code, _, stderr := h.run(postWrite(rel))
		if code != 0 || stderr != "" {
			t.Fatalf("code=%d stderr=%q, want excluded (0/empty)", code, stderr)
		}
	})
}

func TestDiffAwareReconstruct(t *testing.T) {
	// An Edit that does NOT introduce the finding (it was already there) must not
	// be reported: the pre-edit content is reconstructed and diffed.
	h := newHookCall(t)
	rel := h.writeFile("app.py", "y = 2\nx = 1  # FINDING_HIGH\n")
	payload := map[string]any{
		"hook_event_name": "PostToolUse",
		"tool_name":       "Edit",
		"tool_input": map[string]any{
			"file_path":  rel,
			"old_string": "y = 1",
			"new_string": "y = 2",
		},
	}
	code, _, stderr := h.run(payload)
	if code != 0 || stderr != "" {
		t.Fatalf("code=%d stderr=%q: pre-existing finding should not block an unrelated edit", code, stderr)
	}
}

func TestLoopBreaker(t *testing.T) {
	h := newHookCall(t)
	// Four separate files, each introducing the same rule+message finding. The
	// loop breaker counts by rule+message, so the first loopLimit (3) block and
	// the next is downgraded to a warning.
	for i, want := range []int{2, 2, 2, 0} {
		rel := h.writeFile(
			filepath.FromSlash("f"+string(rune('0'+i))+".py"),
			"x = 1  # FINDING_HIGH\n",
		)
		code, _, stderr := h.run(postWrite(filepath.ToSlash(rel)))
		if code != want {
			t.Fatalf("edit %d: code=%d want=%d (stderr=%q)", i, code, want, stderr)
		}
		if i == 3 && !strings.Contains(stderr, "loop breaker") {
			t.Fatalf("edit %d: expected loop-breaker warning, got %q", i, stderr)
		}
	}
}

func TestBashGuard(t *testing.T) {
	bash := func(mode, command string) map[string]any {
		return map[string]any{
			"hook_event_name": "PreToolUse",
			"tool_name":       "Bash",
			"tool_input":      map[string]any{"command": command},
		}
	}
	cases := []struct {
		name     string
		mode     string
		command  string
		wantCode int
		wantErr  string // substring; "" means empty
	}{
		{"warn reports but allows", "warn", "DANGER now", 0, "Trishul warning"},
		{"block stops", "block", "DANGER now", 2, "Trishul blocked this command"},
		{"off is silent", "off", "DANGER now", 0, ""},
		{"safe command passes", "warn", "echo hello", 0, ""},
		{"rm -rf outside workspace flagged", "block", "rm -rf /", 2, "AGENT-BASH-RMRF"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHookCall(t)
			if err := os.WriteFile(filepath.Join(h.cwd, ".trishul.yml"),
				[]byte("agent_hook:\n  bash_guard: "+tc.mode+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			code, _, stderr := h.run(bash(tc.mode, tc.command))
			if code != tc.wantCode {
				t.Fatalf("code=%d want=%d (stderr=%q)", code, tc.wantCode, stderr)
			}
			if tc.wantErr == "" {
				if stderr != "" {
					t.Fatalf("stderr=%q, want empty", stderr)
				}
			} else if !strings.Contains(stderr, tc.wantErr) {
				t.Fatalf("stderr=%q, want substring %q", stderr, tc.wantErr)
			}
		})
	}
}

func TestSummary(t *testing.T) {
	h := newHookCall(t)
	// One blocking edit, then a Stop event should report 1 edit / 1 blocked.
	rel := h.writeFile("app.py", "x = 1  # FINDING_HIGH\n")
	if code, _, _ := h.run(postWrite(rel)); code != 2 {
		t.Fatalf("setup edit code=%d want 2", code)
	}
	code, stdout, _ := h.run(map[string]any{"hook_event_name": "Stop"})
	if code != 0 {
		t.Fatalf("stop code=%d want 0", code)
	}
	if want := "Trishul checked 1 edit, blocked 1 issue\n"; stdout != want {
		t.Fatalf("summary=%q want %q", stdout, want)
	}
}

func TestMalformedPayloadNeverFails(t *testing.T) {
	var out, errb bytes.Buffer
	code := Run(strings.NewReader("{not json"), &out, &errb, Options{Scanner: stubScan, BashScanner: stubBash, TmpRoot: t.TempDir()})
	if code != 0 {
		t.Fatalf("code=%d want 0 on malformed payload", code)
	}
}
