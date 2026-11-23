// Package feedback models production feedback signals on findings (plan P0.5):
// for each finding the App surfaced, what happened to it — shown inline,
// dismissed (with a reason), resolved in a later commit, or left untouched at
// merge. Aggregating these per rule gives a dismiss rate and a fix rate, which
// feed rule tuning and the auto-demotion policy, and can be shared anonymously
// (rule-level counts only, never code or paths).
//
// This is storage-agnostic: it defines the records and the aggregation; the App
// persists Records however it likes and calls Aggregate for /stats.
package feedback

import (
	"sort"
	"time"
)

// Outcome is what became of a surfaced finding.
type Outcome string

const (
	// Shown: surfaced but no further signal yet (still open at observation).
	Shown Outcome = "shown"
	// Dismissed: a reviewer explicitly dismissed it (DismissReason set).
	Dismissed Outcome = "dismissed"
	// Resolved: fixed in a later commit on the PR.
	Resolved Outcome = "resolved"
	// Untouched: left as-is at merge (neither dismissed nor fixed).
	Untouched Outcome = "untouched"
)

// Record is one finding's outcome in one PR.
type Record struct {
	Fingerprint   string    `json:"fingerprint"`
	RuleID        string    `json:"rule_id"`
	Repo          string    `json:"repo,omitempty"`
	Outcome       Outcome   `json:"outcome"`
	DismissReason string    `json:"dismiss_reason,omitempty"`
	At            time.Time `json:"at"`
}

// RuleStats aggregates outcomes for one rule.
type RuleStats struct {
	RuleID      string  `json:"rule_id"`
	Total       int     `json:"total"`
	Shown       int     `json:"shown"`
	Dismissed   int     `json:"dismissed"`
	Resolved    int     `json:"resolved"`
	Untouched   int     `json:"untouched"`
	DismissRate float64 `json:"dismiss_rate"`
	FixRate     float64 `json:"fix_rate"`
}

// Aggregate groups records by rule and computes dismiss/fix rates. DismissRate =
// dismissed/total and FixRate = resolved/total over all surfaced findings for
// the rule. Result is sorted by rule id.
func Aggregate(records []Record) []RuleStats {
	byRule := map[string]*RuleStats{}
	for _, r := range records {
		s := byRule[r.RuleID]
		if s == nil {
			s = &RuleStats{RuleID: r.RuleID}
			byRule[r.RuleID] = s
		}
		s.Total++
		switch r.Outcome {
		case Dismissed:
			s.Dismissed++
		case Resolved:
			s.Resolved++
		case Untouched:
			s.Untouched++
		default:
			s.Shown++
		}
	}
	out := make([]RuleStats, 0, len(byRule))
	for _, s := range byRule {
		if s.Total > 0 {
			s.DismissRate = float64(s.Dismissed) / float64(s.Total)
			s.FixRate = float64(s.Resolved) / float64(s.Total)
		}
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

// AnonStat is the shareable, rule-level-only view: counts and rates, no repo, no
// code, no paths, no fingerprints.
type AnonStat struct {
	RuleID      string  `json:"rule_id"`
	Total       int     `json:"total"`
	DismissRate float64 `json:"dismiss_rate"`
	FixRate     float64 `json:"fix_rate"`
}

// Anonymize strips everything but rule-level counts and rates, for the opt-in
// org setting that shares outcome signal with Armur.
func Anonymize(stats []RuleStats) []AnonStat {
	out := make([]AnonStat, 0, len(stats))
	for _, s := range stats {
		out = append(out, AnonStat{RuleID: s.RuleID, Total: s.Total, DismissRate: s.DismissRate, FixRate: s.FixRate})
	}
	return out
}

// HighDismissRules returns rule ids whose dismiss rate is at or above threshold
// with at least minSample observations — candidates for tuning or demotion.
func HighDismissRules(stats []RuleStats, threshold float64, minSample int) []string {
	var out []string
	for _, s := range stats {
		if s.Total >= minSample && s.DismissRate >= threshold {
			out = append(out, s.RuleID)
		}
	}
	return out
}
