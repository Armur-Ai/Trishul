package prgate

import (
	"github.com/Armur-Ai/Trishul/internal/fileclass"
	"github.com/Armur-Ai/Trishul/internal/findings"
)

// The v2 gate display pipeline (P2.4 + P1.3 integration): take a scan's findings,
// de-noise them (cross-analyzer dedupe → same-rule grouping → repo-level
// clustering), then rank by priority and split into the PR comment budget. This
// is the single function the gate/App call to decide what to show.

// ContextMultiplierFor returns a priority context multiplier for a path, backed
// by file classification (findings in tests/docs/generated files are discounted).
func ContextMultiplierFor(path string) float64 {
	return findings.ContextMultiplier(string(fileclass.ClassifyPath(path)))
}

// GatePipeline runs the full v2 de-noise + budget pipeline over a scan and
// returns the inline/summary/overflow split. maxInline/maxSummary <= 0 use the
// defaults (10/25).
func (s *Scan) GatePipeline(maxInline, maxSummary int) findings.Budget {
	v2 := s.V2Findings()
	v2 = findings.Dedupe(v2)
	v2 = findings.GroupPerFile(v2, findings.DefaultPerFileThreshold)
	v2 = findings.ClusterByRule(v2, findings.DefaultRepoFileThreshold)
	if maxInline <= 0 {
		maxInline = 10
	}
	if maxSummary <= 0 {
		maxSummary = 25
	}
	return findings.ApplyBudget(v2, ContextMultiplierFor, maxInline, maxSummary)
}
