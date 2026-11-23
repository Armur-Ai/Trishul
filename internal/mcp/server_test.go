package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

// req builds a CallToolRequest carrying the given arguments.
func req(args map[string]any) mcp.CallToolRequest {
	var r mcp.CallToolRequest
	r.Params.Arguments = args
	return r
}

// resultText returns the first text content of a tool result.
func resultText(t *testing.T, r *mcp.CallToolResult) string {
	t.Helper()
	if r == nil {
		t.Fatal("nil result")
	}
	if len(r.Content) == 0 {
		t.Fatal("result has no content")
	}
	tc, ok := r.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", r.Content[0])
	}
	return tc.Text
}

func TestWorkspacePath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	// In-workspace paths resolve; escapes are rejected.
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"relative inside", "sub/file.txt", false},
		{"dot", ".", false},
		{"absolute inside", filepath.Join(dir, "x.txt"), false},
		{"dotdot escape", "../outside.txt", true},
		{"deep dotdot escape", "a/../../b", true},
		{"absolute outside", "/etc/passwd", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := workspacePath(tc.input)
			if tc.wantErr != (err != nil) {
				t.Fatalf("workspacePath(%q) err=%v, wantErr=%v", tc.input, err, tc.wantErr)
			}
		})
	}
}

func TestMaskLongTokens(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLEKEY1234567890"
	in := "token=" + secret + " end"
	out := maskLongTokens(in)
	if strings.Contains(out, secret) {
		t.Fatalf("secret not redacted: %q", out)
	}
	if !strings.Contains(out, "...") {
		t.Fatalf("expected a masked preview, got %q", out)
	}
	// Short tokens are left intact.
	if got := maskLongTokens("a short line"); got != "a short line" {
		t.Fatalf("short tokens should be untouched, got %q", got)
	}
}

func writeMCPConfig(t *testing.T, path string, cfg map[string]any) {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestHandleAuditMCPConfig(t *testing.T) {
	ctx := context.Background()

	t.Run("finds insecure remote server", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		writeMCPConfig(t, filepath.Join(dir, "config.json"), map[string]any{
			"mcpServers": map[string]any{
				"evil": map[string]any{"url": "http://evil.example.com/mcp"},
			},
		})
		res, err := handleAuditMCPConfig(ctx, req(map[string]any{"path": "config.json"}))
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("unexpected error result: %s", resultText(t, res))
		}
		var out struct {
			Grade        string `json:"grade"`
			FindingCount int    `json:"finding_count"`
			Findings     []struct {
				CheckID  string
				Severity string
			} `json:"findings"`
		}
		if err := json.Unmarshal([]byte(resultText(t, res)), &out); err != nil {
			t.Fatalf("bad json: %v", err)
		}
		if out.FindingCount == 0 {
			t.Fatal("expected at least one finding")
		}
		if out.Grade == "A" {
			t.Fatalf("expected a non-A grade, got %q", out.Grade)
		}
		found := false
		for _, f := range out.Findings {
			if f.CheckID == "AUDIT-MCP-HTTP" {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected AUDIT-MCP-HTTP finding, got %+v", out.Findings)
		}
	})

	t.Run("output is capped", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		servers := map[string]any{}
		for i := 0; i < maxFindings+5; i++ {
			servers[fmt.Sprintf("s%03d", i)] = map[string]any{
				"url": fmt.Sprintf("http://h%d.example.com/mcp", i),
			}
		}
		writeMCPConfig(t, filepath.Join(dir, "config.json"), map[string]any{"mcpServers": servers})
		res, err := handleAuditMCPConfig(ctx, req(map[string]any{"path": "config.json"}))
		if err != nil {
			t.Fatal(err)
		}
		var out struct {
			FindingCount int  `json:"finding_count"`
			Returned     int  `json:"returned"`
			Truncated    bool `json:"truncated"`
			Findings     []struct {
				CheckID string
			} `json:"findings"`
		}
		if err := json.Unmarshal([]byte(resultText(t, res)), &out); err != nil {
			t.Fatalf("bad json: %v", err)
		}
		if out.FindingCount != maxFindings+5 {
			t.Fatalf("finding_count=%d, want %d", out.FindingCount, maxFindings+5)
		}
		if out.Returned != maxFindings || len(out.Findings) != maxFindings {
			t.Fatalf("returned=%d len=%d, want %d", out.Returned, len(out.Findings), maxFindings)
		}
		if !out.Truncated {
			t.Fatal("expected truncated=true")
		}
	})

	t.Run("rejects path escape", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		res, err := handleAuditMCPConfig(ctx, req(map[string]any{"path": "../../etc"}))
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError {
			t.Fatalf("expected error for escaping path, got: %s", resultText(t, res))
		}
	})

	t.Run("empty path audits home without error", func(t *testing.T) {
		res, err := handleAuditMCPConfig(ctx, req(map[string]any{}))
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("unexpected error: %s", resultText(t, res))
		}
		var out struct {
			Grade string `json:"grade"`
		}
		if err := json.Unmarshal([]byte(resultText(t, res)), &out); err != nil {
			t.Fatalf("bad json: %v", err)
		}
		if out.Grade == "" {
			t.Fatal("expected a grade")
		}
	})
}

func TestHandleSuggestFix(t *testing.T) {
	ctx := context.Background()

	t.Run("returns deterministic patch", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		if err := os.WriteFile(filepath.Join(dir, "schema.sql"),
			[]byte("CREATE TABLE profiles (id int);\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := handleSuggestFix(ctx, req(map[string]any{
			"rule_id": "SUPABASE-RLS-001",
			"path":    "schema.sql",
			"line":    1,
			"message": `Table "profiles" is created without RLS`,
		}))
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("unexpected error: %s", resultText(t, res))
		}
		var out struct {
			RuleID      string `json:"rule_id"`
			Path        string `json:"path"`
			StartLine   int    `json:"start_line"`
			Replacement string `json:"replacement"`
		}
		if err := json.Unmarshal([]byte(resultText(t, res)), &out); err != nil {
			t.Fatalf("bad json: %v", err)
		}
		if out.RuleID != "SUPABASE-RLS-001" || out.Path != "schema.sql" {
			t.Fatalf("unexpected echo: %+v", out)
		}
		if out.StartLine <= 0 {
			t.Fatalf("expected a positive start_line, got %d", out.StartLine)
		}
		if !strings.Contains(out.Replacement, "ENABLE ROW LEVEL SECURITY") ||
			!strings.Contains(out.Replacement, "profiles") {
			t.Fatalf("unexpected replacement: %q", out.Replacement)
		}
	})

	t.Run("no fixer available", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := handleSuggestFix(ctx, req(map[string]any{
			"rule_id": "NO-SUCH-RULE",
			"path":    "a.go",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("unexpected error: %s", resultText(t, res))
		}
		if got := resultText(t, res); got != "no deterministic fix available" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("missing required arg", func(t *testing.T) {
		res, err := handleSuggestFix(ctx, req(map[string]any{"path": "a.go"}))
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError {
			t.Fatal("expected error for missing rule_id")
		}
	})

	t.Run("rejects path escape", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		res, err := handleSuggestFix(ctx, req(map[string]any{
			"rule_id": "SUPABASE-RLS-001",
			"path":    "../../../etc/passwd",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError {
			t.Fatalf("expected error for escaping path, got: %s", resultText(t, res))
		}
	})
}

func TestHandleScanDiff(t *testing.T) {
	ctx := context.Background()

	t.Run("missing args", func(t *testing.T) {
		res, err := handleScanDiff(ctx, req(map[string]any{"dir": "."}))
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError {
			t.Fatal("expected error for missing base_ref")
		}
	})

	t.Run("rejects path escape", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		res, err := handleScanDiff(ctx, req(map[string]any{"dir": "../..", "base_ref": "HEAD~1"}))
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError {
			t.Fatalf("expected error for escaping path, got: %s", resultText(t, res))
		}
	})

	t.Run("reports only introduced findings", func(t *testing.T) {
		if _, err := exec.LookPath("git"); err != nil {
			t.Skip("git not available")
		}
		origWD, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		fixture, err := os.ReadFile(filepath.Join(origWD,
			"../../examples/vibe-coded-app/supabase/migrations/0001_init.sql"))
		if err != nil {
			t.Skip("fixture missing:", err)
		}

		dir := t.TempDir()
		run := func(args ...string) {
			t.Helper()
			cmd := exec.Command("git", append([]string{"-C", dir,
				"-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false"}, args...)...)
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

		t.Chdir(dir)
		res, err := handleScanDiff(ctx, req(map[string]any{"dir": ".", "base_ref": "HEAD~1"}))
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Fatalf("unexpected error: %s", resultText(t, res))
		}
		var out struct {
			BaseRef         string `json:"base_ref"`
			IntroducedCount int    `json:"introduced_count"`
			Returned        int    `json:"returned"`
			Introduced      []struct {
				Path string `json:"path"`
			} `json:"introduced"`
		}
		if err := json.Unmarshal([]byte(resultText(t, res)), &out); err != nil {
			t.Fatalf("bad json: %v", err)
		}
		if out.BaseRef != "HEAD~1" {
			t.Fatalf("base_ref=%q", out.BaseRef)
		}
		if out.IntroducedCount == 0 {
			t.Fatal("expected introduced findings")
		}
		for _, f := range out.Introduced {
			if !strings.HasPrefix(f.Path, "new/") {
				t.Errorf("pre-existing finding reported as introduced: %s", f.Path)
			}
		}
	})
}
