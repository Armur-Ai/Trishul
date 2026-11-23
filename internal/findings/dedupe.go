package findings

import (
	"sort"
	"strings"
)

// Dedupe, grouping, clustering and budgeting (P2.4). These passes turn a raw
// finding list into the smaller, de-noised set a reviewer actually sees. They
// are pure and order-stable so output is deterministic.

// Dedupe collapses cross-analyzer duplicates: findings at the same path and
// within ±1 line that share a CWE are the same issue seen by two analyzers. The
// highest-confidence one is kept and the others' analyzers are recorded in its
// AlsoReportedBy. Findings with no CWE are never merged (too little evidence
// that they are the same issue).
func Dedupe(fs []Finding) []Finding {
	kept := make([]Finding, 0, len(fs))
	for _, f := range fs {
		merged := false
		for i := range kept {
			if sameIssue(kept[i], f) {
				// Keep the higher-confidence record; fold the other's analyzer in.
				if f.Confidence > kept[i].Confidence {
					loser := kept[i]
					f.AlsoReportedBy = mergeAnalyzers(f.AlsoReportedBy, kept[i].AlsoReportedBy, loser.Analyzer)
					kept[i] = f
				} else {
					kept[i].AlsoReportedBy = mergeAnalyzers(kept[i].AlsoReportedBy, f.AlsoReportedBy, f.Analyzer)
				}
				merged = true
				break
			}
		}
		if !merged {
			kept = append(kept, f)
		}
	}
	return kept
}

func sameIssue(a, b Finding) bool {
	if a.Location.Path != b.Location.Path {
		return false
	}
	if abs(a.Location.StartLine-b.Location.StartLine) > 1 {
		return false
	}
	return sharesCWE(a.CWE, b.CWE)
}

func sharesCWE(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	set := make(map[string]bool, len(a))
	for _, x := range a {
		set[strings.ToUpper(strings.TrimSpace(x))] = true
	}
	for _, y := range b {
		if set[strings.ToUpper(strings.TrimSpace(y))] {
			return true
		}
	}
	return false
}

// mergeAnalyzers unions two also-reported lists plus one more analyzer name,
// returning a sorted, de-duplicated, empty-free slice.
func mergeAnalyzers(a, b []string, extra string) []string {
	set := map[string]bool{}
	for _, s := range a {
		if s = strings.TrimSpace(s); s != "" {
			set[s] = true
		}
	}
	for _, s := range b {
		if s = strings.TrimSpace(s); s != "" {
			set[s] = true
		}
	}
	if e := strings.TrimSpace(extra); e != "" {
		set[e] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
