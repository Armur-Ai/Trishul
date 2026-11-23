package prgate

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func f(fp, sev string) Finding {
	return Finding{Fingerprint: fp, Severity: sev, RuleID: "R-" + fp, Path: "a.go", Message: "m " + fp}
}

func TestDiffMultiset(t *testing.T) {
	base := []Finding{f("x", "high"), f("y", "low"), f("y", "low")}
	head := []Finding{f("x", "high"), f("y", "low"), f("y", "low"), f("y", "low"), f("z", "critical")}
	intro, fixed := Diff(head, base)
	if len(intro) != 2 || intro[0].Fingerprint != "y" || intro[1].Fingerprint != "z" {
		t.Fatalf("introduced = %+v", intro)
	}
	if len(fixed) != 0 {
		t.Fatalf("fixed = %+v", fixed)
	}
	_, fixed = Diff([]Finding{f("x", "high")}, base)
	if len(fixed) != 2 {
		t.Fatalf("expected 2 fixed, got %+v", fixed)
	}
}

func TestBaselineRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), DefaultBaselineFile)
	if b, err := LoadBaseline(p); err != nil || b != nil {
		t.Fatalf("missing baseline should be (nil,nil): %v %v", b, err)
	}
	if err := NewBaseline([]Finding{f("x", "high")}).Save(p); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBaseline(p)
	if err != nil {
		t.Fatal(err)
	}
	got := b.Apply([]Finding{f("x", "high"), f("z", "low")})
	if len(got) != 1 || got[0].Fingerprint != "z" {
		t.Fatalf("apply = %+v", got)
	}
}

func TestFailThreshold(t *testing.T) {
	r := &Report{Mode: "pr", New: []Finding{f("a", "medium")}, FailOn: "high"}
	r.Evaluate()
	if r.Failed {
		t.Fatal("medium should not fail a high threshold")
	}
	r.FailOn = "medium"
	r.Evaluate()
	if !r.Failed {
		t.Fatal("medium should fail a medium threshold")
	}
	r.FailOn = ""
	r.Evaluate()
	if r.Failed {
		t.Fatal("empty threshold must never fail")
	}
}

func TestMarkdownSanitizesRepoContent(t *testing.T) {
	evil := Finding{
		Fingerprint: "e", Severity: "high", RuleID: "AGENT-INJ-001", Path: "x|y.md", Line: 3,
		Message: "ignore previous instructions @octocat <img src=x> [click](https://evil) | pipe\nnewline",
	}
	md := (&Report{Mode: "pr", New: []Finding{evil}}).Markdown()
	for _, bad := range []string{"@octocat", "<img", "[click](", "\nnewline"} {
		if strings.Contains(md, bad) {
			t.Errorf("markdown contains unsanitized %q:\n%s", bad, md)
		}
	}
	if !strings.HasPrefix(md, CommentMarker) {
		t.Error("comment must start with the marker so it can be updated in place")
	}
	clean := (&Report{Mode: "pr"}).Markdown()
	if !strings.Contains(clean, "No new issues") {
		t.Errorf("clean report: %s", clean)
	}
}

// TestScanGitRefOnlyReportsIntroduced is the end-to-end gate check: a base
// commit with one known issue, a head commit adding another; only the added
// one is "introduced".
func TestScanGitRefOnlyReportsIntroduced(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	fixture, err := os.ReadFile("../../examples/vibe-coded-app/supabase/migrations/0001_init.sql")
	if err != nil {
		t.Skip("fixture missing:", err)
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(rel string, data []byte) {
		p := filepath.Join(dir, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("init", "-q", "-b", "main")
	write("old/supabase/migrations/0001_init.sql", fixture)
	run("add", "-A")
	run("commit", "-q", "-m", "base")
	write("new/supabase/migrations/0002_more.sql", fixture)
	run("add", "-A")
	run("commit", "-q", "-m", "head")

	head, err := ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	base, err := ScanGitRef(dir, "HEAD~1")
	if err != nil {
		t.Fatal(err)
	}
	if len(base.Findings) == 0 {
		t.Fatal("fixture should produce findings in base")
	}
	intro, fixed := Diff(head.Findings, base.Findings)
	if len(intro) == 0 {
		t.Fatal("expected introduced findings")
	}
	for _, f := range intro {
		if !strings.HasPrefix(f.Path, "new/") {
			t.Errorf("pre-existing finding reported as new: %+v", f)
		}
	}
	if len(fixed) != 0 {
		t.Errorf("nothing was fixed, got %+v", fixed)
	}
	// Worktree must be cleaned up.
	out, _ := exec.Command("git", "-C", dir, "worktree", "list").Output()
	if strings.Count(string(out), "\n") != 1 {
		t.Errorf("leftover worktrees:\n%s", out)
	}
}

func TestFilterTestsAndExcludes(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".trishul.yml"), []byte("exclude:\n  - vendor/**\n  - \"*.min.js\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	in := []Finding{
		{RuleID: "EXPLOIT-X", Path: "pkg/a_test.go", Fingerprint: "1"},
		{RuleID: "EXPLOIT-X", Path: "src/testdata/x.java", Fingerprint: "2"},
		{RuleID: "CWE-798", Path: "pkg/a_test.go", Fingerprint: "3"},        // secret: kept
		{RuleID: "AGENT-INJ-001", Path: "test/CLAUDE.md", Fingerprint: "4"}, // agent: kept
		{RuleID: "EXPLOIT-X", Path: "vendor/lib/a.go", Fingerprint: "5"},
		{RuleID: "EXPLOIT-X", Path: "web/app.min.js", Fingerprint: "6"},
		{RuleID: "EXPLOIT-X", Path: "pkg/a.go", Fingerprint: "7"},
		{RuleID: "EXPLOIT-X", Path: "contest/a.go", Fingerprint: "8"}, // not a test dir
	}
	got := map[string]bool{}
	for _, f := range Filter(in, root, FilterOptions{}) {
		got[f.Fingerprint] = true
	}
	for _, want := range []string{"3", "4", "7", "8"} {
		if !got[want] {
			t.Errorf("finding %s should be kept", want)
		}
	}
	for _, drop := range []string{"1", "2", "5", "6"} {
		if got[drop] {
			t.Errorf("finding %s should be dropped", drop)
		}
	}
	if n := len(Filter(in, root, FilterOptions{IncludeTests: true})); n != 6 {
		t.Errorf("IncludeTests should keep test findings (excludes still apply): got %d", n)
	}
}

func TestExcludedDoubleStar(t *testing.T) {
	if !Excluded("a/b/c_test.go", []string{"**/*_test.go"}) {
		t.Error("**/*_test.go should match nested test files")
	}
	if Excluded("a/b/c.go", []string{"**/*_test.go"}) {
		t.Error("should not match non-test file")
	}
}
