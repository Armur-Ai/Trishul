// Package findingsadapt converts each analyzer's native finding shape into the
// v2 findings.Finding model. It lives apart from internal/findings so that
// package stays a leaf (no analyzer imports); everything that needs to produce
// v2 findings depends on this adapter layer instead.
package findingsadapt

import (
	"strings"

	"github.com/Armur-Ai/Trishul/internal/agentsec"
	"github.com/Armur-Ai/Trishul/internal/exploitability"
	"github.com/Armur-Ai/Trishul/internal/findings"
)

// confidenceFromBand maps a HIGH/MEDIUM/LOW band string to a numeric confidence
// in [0,1]. Analyzers that only know a band get a representative midpoint; those
// that can compute evidence-based confidence should set it directly later.
func confidenceFromBand(band string) float64 {
	switch strings.ToUpper(strings.TrimSpace(band)) {
	case "HIGH":
		return 0.9
	case "MEDIUM", "MED":
		return 0.6
	case "LOW":
		return 0.3
	default:
		return 0.5
	}
}

// splitList turns a comma/space separated identifier list (e.g. "CWE-77, CWE-94")
// into a trimmed slice, dropping empties. Returns nil for an empty input.
func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' })
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// FromAgentFinding converts an agentsec.AgentFinding into a v2 finding. The
// agent-specific context (entry point, trust boundary, affected workflow) is
// preserved as leading evidence steps, and the honest Limitations note is kept
// as a trailing evidence step. A distinguishing pseudo-snippet is built from the
// finding's own fields so multiple agent findings in one file keep distinct
// fingerprints even though agentsec supplies no source window.
func FromAgentFinding(a agentsec.AgentFinding) findings.Finding {
	var ev []findings.EvidenceStep
	addCtx := func(label, val string) {
		if strings.TrimSpace(val) != "" {
			ev = append(ev, findings.EvidenceStep{Path: a.File, Line: a.Line, Note: label + ": " + val})
		}
	}
	addCtx("entry point", a.EntryPoint)
	addCtx("trust boundary", a.TrustBoundary)
	addCtx("affected workflow", a.AffectedWorkflow)
	addCtx("enabled action", a.EnabledAction)
	for _, e := range a.Evidence {
		ev = append(ev, findings.EvidenceStep{Path: a.File, Line: a.Line, Note: e})
	}
	addCtx("limitations", a.Limitations)

	pseudoSnippet := strings.Join([]string{a.CheckID, a.EnabledAction, a.TrustBoundary, firstNonEmpty(a.Evidence...)}, "|")

	return findings.New(findings.Finding{
		RuleID:      a.CheckID,
		Analyzer:    "agentsec",
		Title:       a.Title,
		Message:     firstNonEmpty(a.EnabledAction, a.Title),
		Severity:    findings.Severity(strings.ToUpper(strings.TrimSpace(a.Severity))),
		Confidence:  confidenceFromBand(a.Confidence),
		CWE:         splitList(a.CWE),
		Location:    findings.Location{Path: a.File, StartLine: a.Line},
		Snippet:     pseudoSnippet,
		Evidence:    ev,
		Remediation: findings.Remediation{Text: a.Remediation},
	})
}

// FromExploitability converts an exploitability.Finding into a v2 finding. The
// proven exploitability condition and the "what SCA misses" note are kept as
// leading evidence so a reviewer sees why this is reachable, not just that a
// vulnerable version is present. CVE(s) go into References as CVE URLs.
func FromExploitability(e exploitability.Finding) findings.Finding {
	var ev []findings.EvidenceStep
	if strings.TrimSpace(e.Condition) != "" {
		ev = append(ev, findings.EvidenceStep{Path: e.File, Line: e.Line, Note: "exploitability condition: " + e.Condition})
	}
	if strings.TrimSpace(e.BeyondSCA) != "" {
		ev = append(ev, findings.EvidenceStep{Path: e.File, Line: e.Line, Note: "beyond SCA: " + e.BeyondSCA})
	}
	for _, s := range e.Evidence {
		ev = append(ev, findings.EvidenceStep{Path: e.File, Line: e.Line, Note: s})
	}

	var refs []string
	for _, cve := range splitList(e.CVE) {
		if strings.HasPrefix(strings.ToUpper(cve), "CVE-") {
			refs = append(refs, "https://nvd.nist.gov/vuln/detail/"+strings.ToUpper(cve))
		}
	}

	// Distinguish occurrences by the proven condition so repeated CheckIDs in a
	// file separate; exploitability supplies no raw source window.
	snippet := strings.Join([]string{e.CheckID, e.Condition, firstNonEmpty(e.Evidence...)}, "|")

	return findings.New(findings.Finding{
		RuleID:      e.CheckID,
		Analyzer:    "exploitability",
		Title:       e.Title,
		Message:     firstNonEmpty(e.Condition, e.Title),
		Severity:    findings.Severity(strings.ToUpper(strings.TrimSpace(e.Severity))),
		Confidence:  confidenceFromBand(e.Confidence),
		CWE:         splitList(e.CWE),
		Location:    findings.Location{Path: e.File, StartLine: e.Line},
		Snippet:     snippet,
		Evidence:    ev,
		Remediation: findings.Remediation{Text: e.Remediation},
		References:  refs,
	})
}
