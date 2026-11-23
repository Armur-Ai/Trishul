package projcfg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, ".trishul.yml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad_MissingIsDefault(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "nope.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Profile != "default" || c.Comments.MaxInline != 10 {
		t.Errorf("missing file should give defaults: %+v", c)
	}
}

func TestLoad_Overrides(t *testing.T) {
	c, err := Load(writeCfg(t, `
profile: strict
comments:
  max_inline: 3
gate:
  block_on: [CRITICAL]
  fail_on_new: false
paths:
  ignore:
    - vendor/**
    - "*.min.js"
rules:
  EXPLOIT-*:
    mode: comment
  AGENT-EXEC-002:
    severity: CRITICAL
    enabled: true
experimental: true
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Profile != "strict" || c.Comments.MaxInline != 3 || c.Comments.MaxSummary != 25 {
		t.Errorf("merge wrong: %+v", c.Comments)
	}
	if c.Blocks("HIGH") {
		t.Error("HIGH should not block when block_on=[CRITICAL]")
	}
	if !c.Blocks("critical") {
		t.Error("CRITICAL should block (case-insensitive)")
	}
	if !c.Experimental {
		t.Error("experimental not set")
	}
}

func TestLoad_RejectsUnknownKeys(t *testing.T) {
	_, err := Load(writeCfg(t, "profilex: oops\n"))
	if err == nil {
		t.Error("unknown key should be rejected")
	}
}

func TestResolveRule_MostSpecificGlobWins(t *testing.T) {
	c := Default()
	c.Rules = map[string]RuleOverride{
		"EXPLOIT-*":       {Mode: "monitor"},
		"EXPLOIT-AZURE-*": {Mode: "comment"},
	}
	if got := c.ResolveRule("EXPLOIT-AZURE-BLOB-PUBLIC-001"); got.Mode != "comment" {
		t.Errorf("most-specific glob should win: %+v", got)
	}
	if got := c.ResolveRule("EXPLOIT-SPRING-001"); got.Mode != "monitor" {
		t.Errorf("broad glob should apply: %+v", got)
	}
}

func TestResolveRule_ExactBeatsGlob(t *testing.T) {
	c := Default()
	c.Rules = map[string]RuleOverride{
		"AGENT-*":        {Mode: "monitor"},
		"AGENT-EXEC-002": {Mode: "block"},
	}
	if got := c.ResolveRule("AGENT-EXEC-002"); got.Mode != "block" {
		t.Errorf("exact should beat glob: %+v", got)
	}
}

func TestRuleEnabled(t *testing.T) {
	c := Default()
	no := false
	c.Rules = map[string]RuleOverride{"R-DISABLED": {Enabled: &no}}
	if c.RuleEnabled("R-DISABLED") {
		t.Error("disabled rule reported enabled")
	}
	if !c.RuleEnabled("R-OTHER") {
		t.Error("default should be enabled")
	}
}

func TestPathIgnored(t *testing.T) {
	c := Default()
	c.Paths.Ignore = []string{"vendor/**", "*.min.js", "node_modules"}
	cases := map[string]bool{
		"vendor/x/y.go":       true,
		"vendor":              true,
		"app/bundle.min.js":   false, // path.Match "*.min.js" won't match across '/'
		"bundle.min.js":       true,
		"a/node_modules/p.js": true,
		"src/main.go":         false,
	}
	for p, want := range cases {
		if got := c.PathIgnored(p); got != want {
			t.Errorf("PathIgnored(%q)=%v want %v", p, got, want)
		}
	}
}

func TestExplain(t *testing.T) {
	c := Default()
	out := c.Explain()
	if out == "" || !strings.Contains(out, "block_on=CRITICAL,HIGH") {
		t.Errorf("explain missing gate: %q", out)
	}
}
