// Package precision computes per-rule precision from a labeled corpus (P0.3):
// how often each rule's findings are real versus false positives, with a Wilson
// 95% confidence interval so small samples are not over-read. It is the metric
// the whole Phase-P precision track is measured against (the 76%-FP figure).
//
// The label schema (labels.jsonl, one JSON object per line) and the join of
// scan output to labels live here; the corpus fetch + scan is wired by
// cmd/trishul-bench.
package precision

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
)

// Verdict is a reviewer's judgement of a single finding.
type Verdict string

const (
	// TP: a real, actionable security issue.
	TP Verdict = "tp"
	// TPBenign: technically correct detection but not actionable in context
	// (still counts as "not a false positive" for precision).
	TPBenign Verdict = "tp_benign"
	// FP: the finding is wrong.
	FP Verdict = "fp"
	// Unclear: could not be decided; excluded from precision.
	Unclear Verdict = "unclear"
)

// Label is one reviewed finding.
type Label struct {
	FingerprintV2 string  `json:"fingerprint_v2"`
	Repo          string  `json:"repo"`
	SHA           string  `json:"sha"`
	RuleID        string  `json:"rule_id"`
	Path          string  `json:"path"`
	Line          int     `json:"line"`
	Verdict       Verdict `json:"verdict"`
	Reason        string  `json:"reason"`
	Reviewer      string  `json:"reviewer"`
	Date          string  `json:"date"`
}

// LoadLabels reads labels.jsonl (one Label per non-empty line). Blank lines and
// lines starting with # are skipped.
func LoadLabels(r io.Reader) ([]Label, error) {
	var out []Label
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	ln := 0
	for sc.Scan() {
		ln++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var l Label
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			return nil, fmt.Errorf("labels line %d: %w", ln, err)
		}
		out = append(out, l)
	}
	return out, sc.Err()
}

// RuleStats is the precision summary for one rule.
type RuleStats struct {
	RuleID    string  `json:"rule_id"`
	TP        int     `json:"tp"`
	Benign    int     `json:"benign"`
	FP        int     `json:"fp"`
	Unclear   int     `json:"unclear"`
	Decided   int     `json:"decided"` // tp+benign+fp
	Precision float64 `json:"precision"`
	CILow     float64 `json:"ci_low"`
	CIHigh    float64 `json:"ci_high"`
}

// Compute aggregates labels by rule into per-rule stats, sorted by rule id.
// Precision = (tp + benign) / (tp + benign + fp); unclear is excluded. A rule
// with no decided labels gets precision 0 and a [0,1] interval (fully
// uncertain).
func Compute(labels []Label) []RuleStats {
	byRule := map[string]*RuleStats{}
	for _, l := range labels {
		s := byRule[l.RuleID]
		if s == nil {
			s = &RuleStats{RuleID: l.RuleID}
			byRule[l.RuleID] = s
		}
		switch l.Verdict {
		case TP:
			s.TP++
		case TPBenign:
			s.Benign++
		case FP:
			s.FP++
		default:
			s.Unclear++
		}
	}
	out := make([]RuleStats, 0, len(byRule))
	for _, s := range byRule {
		s.Decided = s.TP + s.Benign + s.FP
		correct := s.TP + s.Benign
		if s.Decided > 0 {
			s.Precision = float64(correct) / float64(s.Decided)
		}
		s.CILow, s.CIHigh = WilsonInterval(correct, s.Decided)
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

// WilsonInterval returns the Wilson score 95% confidence interval for observing
// `success` out of `n`. For n == 0 it returns [0,1] (no information).
func WilsonInterval(success, n int) (low, high float64) {
	if n == 0 {
		return 0, 1
	}
	const z = 1.96
	phat := float64(success) / float64(n)
	nn := float64(n)
	denom := 1 + z*z/nn
	center := (phat + z*z/(2*nn)) / denom
	margin := (z * math.Sqrt(phat*(1-phat)/nn+z*z/(4*nn*nn))) / denom
	low = center - margin
	high = center + margin
	if low < 0 {
		low = 0
	}
	if high > 1 {
		high = 1
	}
	return low, high
}

// Overall returns aggregate precision and FP rate across all decided labels.
func Overall(stats []RuleStats) (precision, fpRate float64, decided int) {
	var correct, fp int
	for _, s := range stats {
		correct += s.TP + s.Benign
		fp += s.FP
		decided += s.Decided
	}
	if decided > 0 {
		precision = float64(correct) / float64(decided)
		fpRate = float64(fp) / float64(decided)
	}
	return precision, fpRate, decided
}
