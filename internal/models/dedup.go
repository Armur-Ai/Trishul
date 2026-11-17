package models

import (
	"fmt"
	"sort"
)

// Deduplicate removes duplicate findings that share the same semantic location.
//
// Findings are grouped by File + RuleID + CWE — the same line-insensitive basis
// used by Finding.ComputeID — so the dedup key and the fingerprint stay
// consistent and neither churns when unrelated edits shift line numbers. (The
// group key omits Tool/Message that ComputeID carries, so the same issue
// reported by different tools still collapses into one.) When a duplicate is
// found, the finding with more populated fields is kept. Returns deduplicated
// findings and metadata about what was removed.
func Deduplicate(findings []Finding) ([]Finding, *DedupMeta) {
	rawCount := len(findings)

	groups := map[string][]int{} // key string -> indices
	for i, f := range findings {
		k := dedupKey(f)
		groups[k] = append(groups[k], i)
	}

	kept := map[int]bool{}
	for _, indices := range groups {
		if len(indices) == 1 {
			kept[indices[0]] = true
			continue
		}

		// Pick the best finding from the group
		bestIdx := indices[0]
		bestScore := fieldScore(findings[bestIdx])
		for _, idx := range indices[1:] {
			score := fieldScore(findings[idx])
			if score > bestScore {
				bestIdx = idx
				bestScore = score
			}
		}

		kept[bestIdx] = true

		// Record duplicate references
		var dupeIDs []string
		for _, idx := range indices {
			if idx != bestIdx {
				findings[idx].ComputeID()
				dupeIDs = append(dupeIDs, findings[idx].ID)
			}
		}
		findings[bestIdx].DuplicateOf = dupeIDs
	}

	// Build result preserving order
	var result []Finding
	for i, f := range findings {
		if kept[i] {
			f.ComputeID()
			result = append(result, f)
		}
	}

	// Sort by severity (highest first), then file, then line
	sort.Slice(result, func(i, j int) bool {
		si := SeverityOrder(result[i].Severity)
		sj := SeverityOrder(result[j].Severity)
		if si != sj {
			return si > sj
		}
		if result[i].File != result[j].File {
			return result[i].File < result[j].File
		}
		return result[i].Line < result[j].Line
	})

	meta := &DedupMeta{
		RawCount:     rawCount,
		AfterDedup:   len(result),
		DupesRemoved: rawCount - len(result),
	}

	return result, meta
}

// dedupKey returns the line-insensitive grouping key for a finding: File +
// RuleID + CWE. This mirrors the fingerprint basis of Finding.ComputeID (minus
// Tool/Message, so cross-tool reports of the same issue still collapse), and
// deliberately excludes the raw line number so grouping survives line shifts.
func dedupKey(f Finding) string {
	return fmt.Sprintf("%s:%s:%s", f.File, f.RuleID, f.CWE)
}

// fieldScore returns a score for how many useful fields a finding has populated.
// Used to pick the "best" finding from a group of duplicates.
func fieldScore(f Finding) int {
	score := 0
	if f.CWE != "" {
		score += 2
	}
	if f.OWASP != "" {
		score += 2
	}
	if f.Remediation != "" {
		score += 3
	}
	if f.Snippet != "" {
		score += 1
	}
	if f.RuleID != "" {
		score += 1
	}
	if f.Message != "" {
		score += 1
	}
	return score
}
