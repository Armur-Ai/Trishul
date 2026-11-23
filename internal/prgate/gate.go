package prgate

import (
	"sort"

	"github.com/Armur-Ai/Trishul/internal/findings"
	"github.com/Armur-Ai/Trishul/internal/projcfg"
)

// RunGateV2 is the v2 gate capstone: it takes a scan plus the resolved
// .trishul.yml config and produces the final gate result — applying inline
// suppressions, dropping ignored paths and disabled rules, de-noising and
// budgeting the survivors, and deciding whether the PR is blocked.
//
// It composes the pieces built for Phase P (suppress → projcfg filters →
// GatePipeline → gate policy) in one place so the CLI and the App behave
// identically.

// GateResult is the outcome of the gate.
type GateResult struct {
	Inline     []findings.Finding
	Summary    []findings.Finding
	Overflow   []findings.Finding
	Suppressed []Suppressed
	Blocked    bool
	// BlockingRuleIDs are the distinct rule ids that caused the block.
	BlockingRuleIDs []string
}

// RunGateV2 runs the full v2 gate over a scan rooted at root.
func RunGateV2(scan *Scan, root string, cfg projcfg.Config) GateResult {
	var res GateResult

	// 1. inline suppressions (trishul-ignore / nosec / ...).
	kept, suppressed := ApplySuppressions(scan.Findings, root)
	res.Suppressed = suppressed

	// 2. config filters: ignored paths and disabled rules.
	filtered := kept[:0:0]
	for _, f := range kept {
		if cfg.PathIgnored(f.Path) {
			continue
		}
		if !cfg.RuleEnabled(f.RuleID) {
			continue
		}
		filtered = append(filtered, f)
	}

	// 3. de-noise + budget via the v2 pipeline.
	budget := (&Scan{Findings: filtered}).GatePipeline(cfg.Comments.MaxInline, cfg.Comments.MaxSummary)
	res.Inline = budget.Inline
	res.Summary = budget.Summary
	res.Overflow = budget.Overflow

	// 4. blocking decision: any surfaced finding whose severity is in the gate's
	// block_on set blocks the PR (unless its rule was set to a non-block mode).
	blockers := map[string]bool{}
	for _, f := range append(append([]findings.Finding{}, budget.Inline...), budget.Summary...) {
		if !cfg.Blocks(string(f.Severity)) {
			continue
		}
		if mode := cfg.ResolveRule(f.RuleID).Mode; mode == "comment" || mode == "monitor" {
			continue
		}
		blockers[f.RuleID] = true
	}
	for id := range blockers {
		res.BlockingRuleIDs = append(res.BlockingRuleIDs, id)
	}
	sort.Strings(res.BlockingRuleIDs)
	res.Blocked = len(res.BlockingRuleIDs) > 0
	return res
}
