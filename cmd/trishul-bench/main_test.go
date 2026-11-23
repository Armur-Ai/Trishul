package main

import (
	"os"
	"path/filepath"
	"testing"
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
