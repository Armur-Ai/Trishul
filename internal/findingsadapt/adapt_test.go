package findingsadapt

import (
	"testing"

	"github.com/Armur-Ai/Trishul/internal/agentsec"
	"github.com/Armur-Ai/Trishul/internal/exploitability"
	"github.com/Armur-Ai/Trishul/internal/findings"
)

func TestFromAgentFinding(t *testing.T) {
	a := agentsec.AgentFinding{
		CheckID:       "AGENT-EXEC-002",
		Title:         "Hook runs untrusted command",
		Severity:      "high",
		Confidence:    "HIGH",
		EntryPoint:    "untrusted PR",
		TrustBoundary: "PR -> agent shell",
		EnabledAction: "curl | sh",
		File:          ".claude/settings.json",
		Line:          12,
		Evidence:      []string{"hook defines postToolUse command", "command pipes remote script to sh"},
		Limitations:   "cannot confirm the remote script is malicious",
		Remediation:   "pin the command; disallow network hooks",
		CWE:           "CWE-77, CWE-94",
	}
	f := FromAgentFinding(a)

	if f.RuleID != "AGENT-EXEC-002" || f.Analyzer != "agentsec" {
		t.Fatalf("rule/analyzer wrong: %+v", f)
	}
	if f.Severity != findings.SeverityHigh {
		t.Errorf("severity=%q", f.Severity)
	}
	if f.Confidence != 0.9 || f.Band != findings.BandHigh {
		t.Errorf("confidence=%v band=%q", f.Confidence, f.Band)
	}
	if len(f.CWE) != 2 || f.CWE[0] != "CWE-77" {
		t.Errorf("cwe=%v", f.CWE)
	}
	// Context + evidence + limitations all preserved as steps.
	if len(f.Evidence) != 6 {
		t.Errorf("evidence steps=%d want 6: %+v", len(f.Evidence), f.Evidence)
	}
	if f.FingerprintV2 == "" {
		t.Error("no fingerprint")
	}
}

func TestFromAgentFinding_DistinctInSameFile(t *testing.T) {
	base := agentsec.AgentFinding{CheckID: "R", Severity: "LOW", Confidence: "LOW", File: "x.json", Line: 1}
	a := base
	a.EnabledAction = "rm -rf /"
	b := base
	b.EnabledAction = "cat ~/.ssh/id_rsa"
	if FromAgentFinding(a).FingerprintV2 == FromAgentFinding(b).FingerprintV2 {
		t.Error("distinct agent findings in one file collided")
	}
}

func TestSplitList(t *testing.T) {
	if got := splitList("CWE-77, CWE-94 ; CWE-22"); len(got) != 3 {
		t.Errorf("splitList=%v", got)
	}
	if splitList("  ") != nil {
		t.Error("blank should be nil")
	}
}

func TestFromExploitability(t *testing.T) {
	e := exploitability.Finding{
		CheckID:     "EXPLOIT-SPRING-ACTUATOR-001",
		CVE:         "CVE-2022-22965",
		Title:       "Actuator env endpoint exposed",
		Severity:    "CRITICAL",
		Confidence:  "HIGH",
		File:        "application.yml",
		Line:        7,
		Condition:   "management.endpoints.web.exposure.include=*",
		BeyondSCA:   "SCA sees the dep; this proves the endpoint is actually exposed",
		Evidence:    []string{"actuator on classpath", "exposure include = *"},
		Remediation: "restrict actuator exposure",
		CWE:         "CWE-200",
	}
	f := FromExploitability(e)
	if f.Analyzer != "exploitability" || f.RuleID != "EXPLOIT-SPRING-ACTUATOR-001" {
		t.Fatalf("bad: %+v", f)
	}
	if f.Severity != findings.SeverityCritical || f.Band != findings.BandHigh {
		t.Errorf("sev/band: %q/%q", f.Severity, f.Band)
	}
	if len(f.References) != 1 || f.References[0] != "https://nvd.nist.gov/vuln/detail/CVE-2022-22965" {
		t.Errorf("refs=%v", f.References)
	}
	if len(f.Evidence) != 4 { // condition + beyondSCA + 2 evidence
		t.Errorf("evidence=%d", len(f.Evidence))
	}
}
