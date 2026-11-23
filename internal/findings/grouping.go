package findings

import "sort"

// Grouping, clustering and budgeting (P2.4, continued). These shrink repetitive
// output so a PR comment stays readable.

// DefaultPerFileThreshold: more than this many of one rule in one file collapse
// to a single grouped finding.
const DefaultPerFileThreshold = 3

// DefaultRepoFileThreshold: a rule firing in more than this many files in one PR
// collapses to a single repo-level summary row.
const DefaultRepoFileThreshold = 20

// GroupPerFile collapses runs of the same rule in the same file: when a rule
// fires more than threshold times in one file, the instances become one finding
// carrying Count and the sorted GroupedLines; the representative kept is the
// highest-severity/-confidence instance. Groups at or below the threshold are
// returned unchanged. Input order of distinct groups is preserved by first
// appearance.
func GroupPerFile(fs []Finding, threshold int) []Finding {
	if threshold < 1 {
		threshold = DefaultPerFileThreshold
	}
	type key struct{ rule, path string }
	idx := map[key]int{} // key -> position in out
	members := map[key][]Finding{}
	var order []key
	for _, f := range fs {
		k := key{f.RuleID, f.Location.Path}
		if _, seen := idx[k]; !seen {
			idx[k] = len(order)
			order = append(order, k)
		}
		members[k] = append(members[k], f)
	}

	var out []Finding
	for _, k := range order {
		ms := members[k]
		if len(ms) <= threshold {
			out = append(out, ms...)
			continue
		}
		rep := ms[0]
		for _, m := range ms[1:] {
			if SeverityWeight(m.Severity) > SeverityWeight(rep.Severity) ||
				(m.Severity == rep.Severity && m.Confidence > rep.Confidence) {
				rep = m
			}
		}
		lines := make([]int, 0, len(ms))
		for _, m := range ms {
			lines = append(lines, m.Location.StartLine)
		}
		sort.Ints(lines)
		rep.Count = len(ms)
		rep.GroupedLines = lines
		out = append(out, rep)
	}
	return out
}

// ClusterByRule collapses a rule that fires across more than fileThreshold
// distinct files into one repo-level summary finding (Count = total instances,
// GroupedLines unset; the message should say "fires in N files"). Rules under
// the threshold pass through unchanged. The representative keeps the first
// instance's location so links still resolve.
func ClusterByRule(fs []Finding, fileThreshold int) []Finding {
	if fileThreshold < 1 {
		fileThreshold = DefaultRepoFileThreshold
	}
	filesByRule := map[string]map[string]bool{}
	countByRule := map[string]int{}
	for _, f := range fs {
		if filesByRule[f.RuleID] == nil {
			filesByRule[f.RuleID] = map[string]bool{}
		}
		filesByRule[f.RuleID][f.Location.Path] = true
		countByRule[f.RuleID]++
	}

	clustered := map[string]bool{}
	var out []Finding
	for _, f := range fs {
		if len(filesByRule[f.RuleID]) <= fileThreshold {
			out = append(out, f)
			continue
		}
		if clustered[f.RuleID] {
			continue // already emitted the one summary row
		}
		clustered[f.RuleID] = true
		f.Count = countByRule[f.RuleID]
		f.Tags = appendUnique(f.Tags, "repo-level-cluster")
		out = append(out, f)
	}
	return out
}

// Budget is the output of applying PR comment/row limits.
type Budget struct {
	Inline   []Finding // shown as inline review comments
	Summary  []Finding // shown as rows in the summary table
	Overflow []Finding // only in the full check run
}

// ApplyBudget ranks findings by priority (using multiplierFor for context) and
// splits them: the top maxInline become inline comments, the next maxSummary go
// in the summary table, and the rest are overflow. Negative limits are treated
// as the defaults 10 and 25.
func ApplyBudget(fs []Finding, multiplierFor func(path string) float64, maxInline, maxSummary int) Budget {
	if maxInline < 0 {
		maxInline = 10
	}
	if maxSummary < 0 {
		maxSummary = 25
	}
	ranked := Rank(fs, multiplierFor)
	var b Budget
	for i, s := range ranked {
		switch {
		case i < maxInline:
			b.Inline = append(b.Inline, s.Finding)
		case i < maxInline+maxSummary:
			b.Summary = append(b.Summary, s.Finding)
		default:
			b.Overflow = append(b.Overflow, s.Finding)
		}
	}
	return b
}

func appendUnique(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}
