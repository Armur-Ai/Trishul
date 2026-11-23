package sarifenrich

import (
	"testing"

	"github.com/Armur-Ai/Trishul/internal/rules"
	"github.com/Armur-Ai/Trishul/pkg/sarif"
)

func testCatalog(t *testing.T) *rules.Catalog {
	t.Helper()
	c, err := rules.LoadCatalog("../rules/testdata/catalog")
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	return c
}

func TestEnrich_PopulatesRuleMetadata(t *testing.T) {
	log := &sarif.Log{Runs: []sarif.Run{{
		Results: []sarif.Result{{RuleID: "AGENT-EXEC-002"}},
	}}}
	Enrich(log, testCatalog(t), map[string]float64{"AGENT-EXEC-002": 0.83})

	rs := log.Runs[0].Tool.Driver.Rules
	if len(rs) != 1 {
		t.Fatalf("want 1 rule entry, got %d", len(rs))
	}
	r := rs[0]
	if r.HelpURI != HelpBaseURL+"/AGENT-EXEC-002" {
		t.Errorf("helpUri=%q", r.HelpURI)
	}
	if r.Help == nil || r.Help.Markdown == "" {
		t.Error("help.markdown not set")
	}
	if r.Properties["security-severity"] != "8.0" {
		t.Errorf("security-severity=%v want 8.0 (HIGH)", r.Properties["security-severity"])
	}
	if r.Properties["precision"] != 0.83 {
		t.Errorf("precision=%v", r.Properties["precision"])
	}
	tags, _ := r.Properties["tags"].([]string)
	var hasSecurity, hasCWE bool
	for _, tg := range tags {
		if tg == "security" {
			hasSecurity = true
		}
		if tg == "external/cwe/cwe-77" {
			hasCWE = true
		}
	}
	if !hasSecurity || !hasCWE {
		t.Errorf("tags=%v (want security + cwe-77)", tags)
	}
}

func TestEnrich_CreatesMissingRuleEntries(t *testing.T) {
	log := &sarif.Log{Runs: []sarif.Run{{Results: []sarif.Result{{RuleID: "UNKNOWN-RULE"}}}}}
	Enrich(log, testCatalog(t), nil)
	rs := log.Runs[0].Tool.Driver.Rules
	if len(rs) != 1 || rs[0].ID != "UNKNOWN-RULE" {
		t.Fatalf("missing rule entry not created: %+v", rs)
	}
	// Even without catalog data it should get a helpUri and security tag.
	if rs[0].HelpURI == "" {
		t.Error("helpUri not set for uncatalogued rule")
	}
}

func TestCweNumber(t *testing.T) {
	if cweNumber("CWE-79") != "79" {
		t.Error("CWE-79")
	}
	if cweNumber("not-a-cwe") != "" {
		t.Error("garbage should be empty")
	}
}

func TestSecuritySeverity(t *testing.T) {
	if securitySeverity("CRITICAL") != "9.5" || securitySeverity("low") != "3.0" {
		t.Error("severity mapping wrong")
	}
}
