package precision

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Markdown renders per-rule precision as a table plus an overall line, suitable
// for docs/rules/precision.md and the bench output.
func Markdown(stats []RuleStats) string {
	var b strings.Builder
	p, fp, decided := Overall(stats)
	fmt.Fprintf(&b, "# Rule precision\n\n")
	fmt.Fprintf(&b, "Overall precision **%.1f%%** (FP rate %.1f%%) over %d decided labels.\n\n", p*100, fp*100, decided)
	b.WriteString("| Rule | TP | Benign | FP | Precision | 95% CI |\n")
	b.WriteString("|------|----|--------|----|-----------|--------|\n")
	for _, s := range stats {
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %.0f%% | %.0f–%.0f%% |\n",
			s.RuleID, s.TP, s.Benign, s.FP, s.Precision*100, s.CILow*100, s.CIHigh*100)
	}
	return b.String()
}

// JSON renders stats as indented JSON.
func JSON(stats []RuleStats) ([]byte, error) {
	return json.MarshalIndent(stats, "", "  ")
}

// Join matches scanned fingerprints to labels. foundByRule maps a rule id to the
// set of fingerprints the scan emitted for it; labels are the reviewed verdicts.
// It returns the labels whose fingerprints were actually produced by the scan
// (so stale labels for findings that no longer fire are dropped) and the list of
// unlabeled findings per rule (the labeling queue).
func Join(foundByRule map[string][]string, labels []Label) (matched []Label, unlabeled map[string][]string) {
	labelByFP := make(map[string]Label, len(labels))
	for _, l := range labels {
		labelByFP[l.FingerprintV2] = l
	}
	unlabeled = map[string][]string{}
	seen := map[string]bool{}
	for rule, fps := range foundByRule {
		for _, fp := range fps {
			if l, ok := labelByFP[fp]; ok {
				if !seen[fp] {
					matched = append(matched, l)
					seen[fp] = true
				}
			} else {
				unlabeled[rule] = append(unlabeled[rule], fp)
			}
		}
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].FingerprintV2 < matched[j].FingerprintV2 })
	for rule := range unlabeled {
		sort.Strings(unlabeled[rule])
	}
	return matched, unlabeled
}

// LabelingQueue orders rules for labeling by expected information gain: fewest
// labels first, so under-sampled rules get attention before well-covered ones.
func LabelingQueue(stats []RuleStats) []string {
	type rc struct {
		id string
		n  int
	}
	rcs := make([]rc, 0, len(stats))
	for _, s := range stats {
		rcs = append(rcs, rc{s.RuleID, s.Decided})
	}
	sort.Slice(rcs, func(i, j int) bool {
		if rcs[i].n != rcs[j].n {
			return rcs[i].n < rcs[j].n
		}
		return rcs[i].id < rcs[j].id
	})
	out := make([]string, len(rcs))
	for i, r := range rcs {
		out[i] = r.id
	}
	return out
}
