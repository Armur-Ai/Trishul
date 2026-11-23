package precision

// Resolve joins scanned findings to reviewer labels (P0.3). The plan's join key
// is the fingerprint, with a fallback to rule + path + line within ±3 — the
// fallback matters because a scan's fingerprint scheme may differ from the one a
// label was recorded under, yet the finding is clearly the same.

// Found is a scanned finding to be matched against labels.
type Found struct {
	RuleID      string
	Path        string
	Line        int
	Fingerprint string
}

// LineTolerance is the ± line window for the location fallback.
const LineTolerance = 3

// Resolve returns the labels that correspond to scanned findings (so precision
// is computed only over findings the scan actually produces) and the findings
// that have no label yet (the labeling queue). Each label is used at most once.
func Resolve(found []Found, labels []Label) (matched []Label, unlabeled []Found) {
	byFP := make(map[string]int, len(labels)) // fingerprint -> label index
	for i, l := range labels {
		if l.FingerprintV2 != "" {
			byFP[l.FingerprintV2] = i
		}
	}
	usedLabel := make([]bool, len(labels))

	for _, f := range found {
		if f.Fingerprint != "" {
			if i, ok := byFP[f.Fingerprint]; ok && !usedLabel[i] {
				usedLabel[i] = true
				matched = append(matched, labels[i])
				continue
			}
		}
		if i := locationMatch(f, labels, usedLabel); i >= 0 {
			usedLabel[i] = true
			matched = append(matched, labels[i])
			continue
		}
		unlabeled = append(unlabeled, f)
	}
	return matched, unlabeled
}

func locationMatch(f Found, labels []Label, used []bool) int {
	best := -1
	bestDelta := LineTolerance + 1
	for i, l := range labels {
		if used[i] || l.RuleID != f.RuleID || l.Path != f.Path {
			continue
		}
		d := f.Line - l.Line
		if d < 0 {
			d = -d
		}
		if d <= LineTolerance && d < bestDelta {
			best, bestDelta = i, d
		}
	}
	return best
}

// FoundByRule groups fingerprints by rule id (used by Join for the fast path).
func FoundByRule(found []Found) map[string][]string {
	m := map[string][]string{}
	for _, f := range found {
		m[f.RuleID] = append(m[f.RuleID], f.Fingerprint)
	}
	return m
}
