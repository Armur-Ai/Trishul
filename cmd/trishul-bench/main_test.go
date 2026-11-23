package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Armur-Ai/Trishul/internal/precision"
)

func TestParse(t *testing.T) {
	f, err := parse([]string{"--labels", "l.jsonl", "--rules", "R1,R2", "--md", "o.md"})
	if err != nil {
		t.Fatal(err)
	}
	if f.labels != "l.jsonl" || f.rules != "R1,R2" || f.md != "o.md" {
		t.Errorf("parse wrong: %+v", f)
	}
	if _, err := parse([]string{"--labels"}); err == nil {
		t.Error("missing value should error")
	}
	if _, err := parse([]string{"--bogus", "x"}); err == nil {
		t.Error("unknown flag should error")
	}
}

func TestRuleSelected(t *testing.T) {
	if !ruleSelected("AGENT-EXEC-002", "agent-exec-002, VIBE-001") {
		t.Error("should match case-insensitively")
	}
	if ruleSelected("X", "Y,Z") {
		t.Error("should not match")
	}
}

func TestRunReport_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	labels := filepath.Join(dir, "labels.jsonl")
	body := `{"rule_id":"R","verdict":"tp","fingerprint_v2":"a"}
{"rule_id":"R","verdict":"fp","fingerprint_v2":"b"}
{"rule_id":"S","verdict":"fp","fingerprint_v2":"c"}`
	if err := os.WriteFile(labels, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	md := filepath.Join(dir, "out.md")
	jsonOut := filepath.Join(dir, "out.json")
	if err := runReport([]string{"--labels", labels, "--md", md, "--json", jsonOut}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{md, jsonOut} {
		info, err := os.Stat(p)
		if err != nil || info.Size() == 0 {
			t.Errorf("expected non-empty %s: %v", p, err)
		}
	}
}

func TestRunReport_RulesFilter(t *testing.T) {
	dir := t.TempDir()
	labels := filepath.Join(dir, "labels.jsonl")
	os.WriteFile(labels, []byte(`{"rule_id":"R","verdict":"tp"}
{"rule_id":"S","verdict":"fp"}`), 0o644)
	jsonOut := filepath.Join(dir, "o.json")
	if err := runReport([]string{"--labels", labels, "--rules", "R", "--json", jsonOut}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(jsonOut)
	if !contains(string(data), `"rule_id": "R"`) || contains(string(data), `"rule_id": "S"`) {
		t.Errorf("rules filter failed:\n%s", data)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestLabelLoop(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "x.go"), []byte("package x\nvar k = \"SECRETVALUE0123456789ABCDEFGHIJ\"\n"), 0o644)
	unlabeled := []precision.Found{
		{RuleID: "R1", Path: "x.go", Line: 2, Fingerprint: "fp1"},
		{RuleID: "R2", Path: "x.go", Line: 2, Fingerprint: "fp2"},
	}
	in := bufio.NewScanner(strings.NewReader("fp key committed\n\n")) // label first, skip second
	var out, sink strings.Builder
	n, err := labelLoop(dir, unlabeled, in, &out, &sink)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("labeled=%d want 1 (second skipped)", n)
	}
	if strings.Contains(out.String(), "SECRETVALUE0123456789ABCDEFGHIJ") {
		t.Error("secret leaked to output")
	}
	ls, _ := precision.LoadLabels(strings.NewReader(sink.String()))
	if len(ls) != 1 || ls[0].Verdict != precision.FP || ls[0].Reason != "key committed" {
		t.Errorf("appended label wrong: %+v", ls)
	}
}

func TestLabelLoop_RejectsBadVerdict(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "x.go"), []byte("a\nb\n"), 0o644)
	in := bufio.NewScanner(strings.NewReader("maybe nope\n"))
	var out, sink strings.Builder
	n, _ := labelLoop(dir, []precision.Found{{RuleID: "R", Path: "x.go", Line: 1}}, in, &out, &sink)
	if n != 0 || sink.Len() != 0 {
		t.Errorf("bad verdict should not append: n=%d sink=%q", n, sink.String())
	}
}
