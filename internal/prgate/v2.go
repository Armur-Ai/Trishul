package prgate

import (
	"strings"

	"github.com/Armur-Ai/Trishul/internal/findings"
)

// v2 bridge (P1.1). prgate's own Finding is a compact gate-internal shape; this
// converts it to the richer findings.Finding so the gate can run the v2 display
// pipeline (dedupe → grouping → priority → budget) on scan output. The analyzers
// emitting findings.Finding natively is a larger follow-up; until then this
// bridge is the seam.
//
// Note: prgate.Finding carries no snippet or confidence, so the v2 finding uses
// the message as its fingerprint window and a neutral default confidence. For
// prgate's own base/head diff the native Fingerprint is still authoritative; the
// v2 fingerprint here is only for display-layer grouping.

// DefaultBridgeConfidence is used when the source finding has no confidence.
const DefaultBridgeConfidence = 0.7

// ToV2 converts one gate finding to a v2 finding.
func (f Finding) ToV2() findings.Finding {
	fn := findings.New(findings.Finding{
		RuleID:     f.RuleID,
		Analyzer:   analyzerFor(f.RuleID),
		Title:      f.RuleID,
		Message:    f.Message,
		Severity:   findings.Severity(strings.ToUpper(f.Severity)),
		Confidence: DefaultBridgeConfidence,
		Location:   findings.Location{Path: f.Path, StartLine: f.Line},
		Snippet:    f.Message,
	})
	// Preserve the gate's authoritative fingerprint (New recomputes a v2 one).
	if f.Fingerprint != "" {
		fn.FingerprintV2 = f.Fingerprint
	}
	return fn
}

// V2Findings converts all of a scan's findings to v2.
func (s *Scan) V2Findings() []findings.Finding {
	out := make([]findings.Finding, 0, len(s.Findings))
	for _, f := range s.Findings {
		out = append(out, f.ToV2())
	}
	return out
}

// analyzerFor guesses the producing analyzer family from a rule id prefix, for
// display grouping and the also_reported_by field.
func analyzerFor(ruleID string) string {
	switch {
	case strings.HasPrefix(ruleID, "AGENT-"):
		return "agentsec"
	case strings.HasPrefix(ruleID, "EXPLOIT-"):
		return "exploitability"
	case strings.HasPrefix(ruleID, "VIBE-"):
		return "vibe"
	case strings.HasPrefix(ruleID, "SUPABASE"):
		return "supabase"
	case strings.HasPrefix(ruleID, "FIREBASE"):
		return "firebase"
	case strings.HasPrefix(ruleID, "CLIENT-SECRET"), strings.HasPrefix(ruleID, "SECRET"):
		return "secrets"
	default:
		return "trishul"
	}
}
