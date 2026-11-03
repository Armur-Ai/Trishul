// Package suite adapts Trishul's native scan results into the shared Armur suite
// contract (github.com/Armur-Ai/armur-contracts), so Akira/Engira can consume
// Trishul's code evidence through the common vocabulary.
//
// It preserves the honest distinctions the contract requires: a native tool
// result is a declared SourceClaim, not a confirmed finding, unless Trishul
// actually verified it (DAST/exploit) — only then is it adjudicated/runtime.
// Secrets, dependency advisories, and non-security quality issues are mapped to
// their correctly-typed records, never flattened into "vulnerabilities".
package suite

import (
	"time"

	"github.com/Armur-Ai/Trishul/internal/models"
	contracts "github.com/Armur-Ai/armur-contracts"
)

// EmitEnvelope wraps the emitted CodeAnalysisBundle in a versioned suite
// envelope attributed to Trishul, ready to send to Akira/Engira over any
// contracts transport.
func EmitEnvelope(r models.ScanResult, producerVersion string) (contracts.Envelope, error) {
	bundle := EmitCodeAnalysisBundle(r, producerVersion)
	return contracts.NewEnvelope(
		contracts.NSTrishul,
		contracts.Producer{Product: "trishul", Version: producerVersion},
		"CodeAnalysisBundle", bundle,
	)
}

// EmitCodeAnalysisBundle converts a Trishul ScanResult into a
// contracts.CodeAnalysisBundle. producerVersion stamps the Trishul build.
func EmitCodeAnalysisBundle(r models.ScanResult, producerVersion string) contracts.CodeAnalysisBundle {
	b := contracts.CodeAnalysisBundle{
		RunID:       r.TaskID,
		Analyzers:   analyzers(r.Meta.ToolsRun, producerVersion),
		Incremental: false,
		Coverage: contracts.AnalysisCoverage{
			Analyzed: r.Meta.FileCount,
		},
		StartedAt:  time.Now().UTC(),
		FinishedAt: time.Now().UTC(),
	}
	if r.Meta.Language != "" {
		b.Coverage.Languages = []string{r.Meta.Language}
	}
	pillars := map[string]bool{}
	for _, f := range r.Findings {
		switch classifyFinding(f) {
		case kindSecret:
			pillars["secrets"] = true
			b.Secrets = append(b.Secrets, toSecret(f))
		case kindDependency:
			pillars["dependency"] = true
			b.SourceClaims = append(b.SourceClaims, toSourceClaim(f, contracts.ClaimDependencyAdvisory))
		case kindSecurity:
			pillars["sast"] = true
			b.SourceClaims = append(b.SourceClaims, toSourceClaim(f, contracts.ClaimSourceWeakness))
		default: // quality
			b.Issues = append(b.Issues, toCodeIssue(f))
		}
	}
	for p := range pillars {
		b.Pillars = append(b.Pillars, p)
	}
	return b
}

type findingKind int

const (
	kindSecurity findingKind = iota
	kindSecret
	kindDependency
	kindQuality
)

func classifyFinding(f models.Finding) findingKind {
	switch f.Source {
	case "secrets":
		return kindSecret
	case "sca":
		return kindDependency
	}
	if f.Category == "security_issues" || f.Source == "sast" || f.Source == "dast" ||
		f.Source == "iac" || f.Source == "exploit" || f.Source == "attack_path" {
		return kindSecurity
	}
	return kindQuality
}

func toSourceClaim(f models.Finding, kind contracts.ClaimKind) contracts.SourceClaim {
	return contracts.SourceClaim{
		Fingerprint: f.ID,
		Tool:        f.Tool,
		RuleID:      f.RuleID,
		Kind:        kind,
		Severity:    severity(f.Severity),
		Locations:   []contracts.CodeLocation{{Path: f.File, StartLine: f.Line, EndLine: f.EndLine}},
		ProposedCWE: cweList(f.CWE),
		Confidence:  f.Confidence,
		Status:      status(f),
	}
}

func toSecret(f models.Finding) contracts.SecretCandidate {
	return contracts.SecretCandidate{
		Detector: f.Tool,
		Location: contracts.CodeLocation{Path: f.File, StartLine: f.Line},
		Status:   status(f),
	}
}

func toCodeIssue(f models.Finding) contracts.CodeIssue {
	kind := contracts.IssueInformational
	switch f.Category {
	case "antipatterns_bugs":
		kind = contracts.IssueReliability
	case "complex_functions":
		kind = contracts.IssueMaintainability
	}
	return contracts.CodeIssue{
		Kind:       kind,
		Rule:       f.RuleID,
		Locations:  []contracts.CodeLocation{{Path: f.File, StartLine: f.Line}},
		Impact:     f.Message,
		Confidence: f.Confidence,
	}
}

// status keeps declared vs adjudicated vs runtime-confirmed honest.
func status(f models.Finding) contracts.ClaimStatus {
	if !f.Confirmed {
		return contracts.StatusDeclared
	}
	switch f.Source {
	case "dast", "exploit", "attack_path":
		return contracts.StatusRuntimeConfirmed
	default:
		return contracts.StatusAdjudicatedSource
	}
}

func severity(s models.Severity) string {
	switch s {
	case models.SeverityCritical:
		return "critical"
	case models.SeverityHigh:
		return "high"
	case models.SeverityMedium:
		return "medium"
	case models.SeverityLow:
		return "low"
	default:
		return "info"
	}
}

func cweList(cwe string) []string {
	if cwe == "" {
		return nil
	}
	return []string{cwe}
}

func analyzers(tools []string, version string) []contracts.AnalyzerPin {
	out := make([]contracts.AnalyzerPin, 0, len(tools))
	for _, t := range tools {
		out = append(out, contracts.AnalyzerPin{Name: t, Version: version})
	}
	return out
}
