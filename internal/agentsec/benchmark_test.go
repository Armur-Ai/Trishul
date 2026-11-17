package agentsec

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// Agent-security benchmark (spec §F).
//
// A labelled corpus of small, PR-shaped fixture repositories lives under
// testdata/agentsec/benchmark/:
//
//   - malicious/<case>/ — each a tiny repo that SHOULD yield at least one
//     finding. Treated as a POSITIVE: the detector is correct when it flags it
//     (recall), one case per attack class.
//   - benign/<case>/ — the hard false-positive cases that must yield NOTHING.
//     Treated as a NEGATIVE: the detector is correct when it stays quiet. A
//     LOW-confidence finding is tolerated (e.g. a security-research doc that
//     quotes an injection is downgraded to LOW, never asserted as a live attack),
//     so a benign case counts as a false positive only when it emits a finding
//     with confidence above LOW.
//
// The test runs AnalyzePath on every case, computes precision / recall / FP count,
// logs the metrics and every miss/false-positive for debuggability, and asserts
// the measured bars. The thresholds below are set at the values the corpus
// actually achieves (see the t.Log output), not aspirational numbers.
const (
	// benchMinRecall: fraction of malicious cases that must produce >=1 finding.
	benchMinRecall = 1.0
	// benchMinPrecision: TP / (TP + FP) over the whole corpus.
	benchMinPrecision = 1.0
	// benchMaxFalsePositives: benign cases allowed to fire above LOW confidence.
	benchMaxFalsePositives = 0
)

// caseResult is the outcome of analysing one fixture case.
type caseResult struct {
	name     string // "<class>/<case>"
	findings []AgentFinding
	fired    bool     // for malicious: any finding; for benign: any finding > LOW
	checkIDs []string // distinct check IDs seen (for debug logs)
}

func TestAgentSecBenchmark(t *testing.T) {
	if Registered() == 0 {
		t.Skip("no components registered in this build")
	}
	root := filepath.Join("testdata", "agentsec", "benchmark")

	malicious := runBenchGroup(t, filepath.Join(root, "malicious"), false)
	benign := runBenchGroup(t, filepath.Join(root, "benign"), true)

	if len(malicious) == 0 || len(benign) == 0 {
		t.Fatalf("empty corpus: malicious=%d benign=%d (expected both populated)", len(malicious), len(benign))
	}

	// Positives = malicious cases that fired; a benign case that fires is a FP.
	tp, fn := 0, 0
	for _, c := range malicious {
		if c.fired {
			tp++
		} else {
			fn++
			t.Logf("MISS (malicious not detected): %s — findings=%d %v", c.name, len(c.findings), c.checkIDs)
		}
	}
	fp, tn := 0, 0
	for _, c := range benign {
		if c.fired {
			fp++
			t.Logf("FALSE POSITIVE (benign flagged > LOW): %s — %v", c.name, benchDescribe(c.findings))
		} else {
			tn++
		}
	}

	recall := ratio(tp, tp+fn)
	precision := ratio(tp, tp+fp)

	t.Logf("agentsec benchmark: cases malicious=%d benign=%d", len(malicious), len(benign))
	t.Logf("  TP=%d FN=%d FP=%d TN=%d", tp, fn, fp, tn)
	t.Logf("  recall=%.3f precision=%.3f false_positives=%d", recall, precision, fp)

	if recall < benchMinRecall {
		t.Errorf("recall %.3f below bar %.3f (%d/%d malicious cases detected)", recall, benchMinRecall, tp, tp+fn)
	}
	if precision < benchMinPrecision {
		t.Errorf("precision %.3f below bar %.3f", precision, benchMinPrecision)
	}
	if fp > benchMaxFalsePositives {
		t.Errorf("false positives %d exceed bar %d", fp, benchMaxFalsePositives)
	}
}

// runBenchGroup analyses every immediate subdirectory of groupDir. When benign is
// true a case "fires" only on a finding above LOW confidence; otherwise any
// finding counts.
func runBenchGroup(t *testing.T, groupDir string, benign bool) []caseResult {
	t.Helper()
	entries, err := os.ReadDir(groupDir)
	if err != nil {
		t.Fatalf("read corpus dir %s: %v", groupDir, err)
	}
	var out []caseResult
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		caseDir := filepath.Join(groupDir, e.Name())
		findings, err := AnalyzePath(caseDir)
		if err != nil {
			t.Fatalf("AnalyzePath(%s): %v", caseDir, err)
		}
		fired := false
		for _, f := range findings {
			if benign {
				if f.Confidence != "LOW" {
					fired = true
					break
				}
			} else {
				fired = true
				break
			}
		}
		out = append(out, caseResult{
			name:     filepath.Base(groupDir) + "/" + e.Name(),
			findings: findings,
			fired:    fired,
			checkIDs: benchCheckIDs(findings),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func benchCheckIDs(fs []AgentFinding) []string {
	seen := map[string]bool{}
	var ids []string
	for _, f := range fs {
		if !seen[f.CheckID] {
			seen[f.CheckID] = true
			ids = append(ids, f.CheckID)
		}
	}
	sort.Strings(ids)
	return ids
}

func benchDescribe(fs []AgentFinding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, fmt.Sprintf("%s[%s/%s]", f.CheckID, f.Severity, f.Confidence))
	}
	return out
}

func ratio(num, den int) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den)
}
