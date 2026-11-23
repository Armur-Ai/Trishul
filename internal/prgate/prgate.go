// Package prgate turns Trishul scans into a pull-request gate: it scans a
// checkout with the built-in analyzers, normalizes findings to stable,
// line-insensitive fingerprints, and diffs a PR head against its base so only
// findings the PR introduces are reported.
//
// It is shared by the trishul-ci binary (used by the GitHub Action) and the
// trishul-app GitHub App server, so both surfaces produce identical results.
package prgate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Armur-Ai/Trishul/internal/tasks"
	"github.com/Armur-Ai/Trishul/pkg/sarif"
)

// Finding is a normalized scan finding.
type Finding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Path        string `json:"path"`
	Line        int    `json:"line,omitempty"`
	Message     string `json:"message"`
	Fingerprint string `json:"fingerprint"`
}

// Scan is the result of scanning one tree.
type Scan struct {
	SARIF    *sarif.Log
	Findings []Finding
	Errors   []tasks.ScanError
}

// severityRank orders severities; unknown values rank as medium.
var severityRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// Rank returns the numeric rank of a severity (info=0 … critical=4).
func Rank(sev string) int {
	if r, ok := severityRank[strings.ToLower(sev)]; ok {
		return r
	}
	return 2
}

// ValidSeverity reports whether s is a recognised severity name.
func ValidSeverity(s string) bool {
	_, ok := severityRank[strings.ToLower(s)]
	return ok
}

// ScanDir runs the built-in analyzers over dir. It never executes repository
// content, so it is safe on untrusted pull-request heads.
func ScanDir(dir string) (*Scan, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	results, scanErrs, err := tasks.RunBuiltinScan(abs)
	if err != nil {
		return nil, err
	}
	log := sarif.FromScanResults(results, "")
	normalizeSARIF(log, abs)
	return &Scan{SARIF: log, Findings: FromSARIF(log), Errors: scanErrs}, nil
}

// normalizeSARIF rewrites any absolute paths under root to repo-relative ones
// (in locations and messages) and recomputes fingerprints from the relative
// form, so a scan of the base checkout in a different temp directory yields
// the same identities as a scan of the head.
func normalizeSARIF(log *sarif.Log, root string) {
	prefix := filepath.ToSlash(root) + "/"
	for ri := range log.Runs {
		for i := range log.Runs[ri].Results {
			r := &log.Runs[ri].Results[i]
			r.Message.Text = strings.ReplaceAll(r.Message.Text, prefix, "")
			path := ""
			for li := range r.Locations {
				u := &r.Locations[li].PhysicalLocation.ArtifactLocation.URI
				*u = strings.TrimPrefix(filepath.ToSlash(*u), prefix)
				*u = strings.TrimPrefix(*u, "./")
				if li == 0 {
					path = *u
				}
			}
			if r.PartialFingerprints == nil {
				r.PartialFingerprints = map[string]string{}
			}
			r.PartialFingerprints["trishul/v1"] = Fingerprint(r.RuleID, path, r.Message.Text)
		}
	}
}

// Fingerprint is the stable identity of a finding. It deliberately excludes
// the line number so unrelated edits above a finding don't make it "new".
func Fingerprint(ruleID, path, message string) string {
	sum := sha256.Sum256([]byte(ruleID + "|" + path + "|" + message))
	return hex.EncodeToString(sum[:])[:16]
}

// FromSARIF extracts normalized findings from a SARIF log, sorted by
// severity (desc), then path and line.
func FromSARIF(log *sarif.Log) []Finding {
	var out []Finding
	for _, run := range log.Runs {
		for _, r := range run.Results {
			f := Finding{RuleID: r.RuleID, Message: r.Message.Text, Severity: "medium"}
			if s, ok := r.Properties["severity"].(string); ok && s != "" {
				f.Severity = strings.ToLower(s)
			} else {
				f.Severity = levelToSeverity(r.Level)
			}
			if len(r.Locations) > 0 {
				f.Path = r.Locations[0].PhysicalLocation.ArtifactLocation.URI
				if reg := r.Locations[0].PhysicalLocation.Region; reg != nil {
					f.Line = reg.StartLine
				}
			}
			f.Fingerprint = r.PartialFingerprints["trishul/v1"]
			if f.Fingerprint == "" {
				f.Fingerprint = Fingerprint(f.RuleID, f.Path, f.Message)
			}
			out = append(out, f)
		}
	}
	SortFindings(out)
	return out
}

// SortFindings orders findings by severity (desc), path, line, rule.
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if Rank(a.Severity) != Rank(b.Severity) {
			return Rank(a.Severity) > Rank(b.Severity)
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.RuleID < b.RuleID
	})
}

func levelToSeverity(level string) string {
	switch level {
	case "error":
		return "high"
	case "note":
		return "low"
	default:
		return "medium"
	}
}

// Diff splits head findings into those the PR introduced (absent from base)
// and those it fixed (present in base, absent from head). Matching is by
// fingerprint as a multiset, so a PR that adds a second copy of an existing
// issue still reports the new copy.
func Diff(head, base []Finding) (introduced, fixed []Finding) {
	baseCount := map[string]int{}
	for _, f := range base {
		baseCount[f.Fingerprint]++
	}
	headCount := map[string]int{}
	for _, f := range head {
		headCount[f.Fingerprint]++
		if baseCount[f.Fingerprint] > 0 {
			baseCount[f.Fingerprint]--
			continue
		}
		introduced = append(introduced, f)
	}
	for _, f := range base {
		if headCount[f.Fingerprint] > 0 {
			headCount[f.Fingerprint]--
			continue
		}
		fixed = append(fixed, f)
	}
	return introduced, fixed
}

// AtOrAbove returns findings whose severity is at least min.
func AtOrAbove(fs []Finding, min string) []Finding {
	if min == "" {
		return fs
	}
	t := Rank(min)
	var out []Finding
	for _, f := range fs {
		if Rank(f.Severity) >= t {
			out = append(out, f)
		}
	}
	return out
}

// FilterSARIF keeps only SARIF results whose fingerprint is in keep. Used to
// upload just the PR's new findings (or just non-baselined ones).
func FilterSARIF(log *sarif.Log, keep []Finding) *sarif.Log {
	want := map[string]int{}
	for _, f := range keep {
		want[f.Fingerprint]++
	}
	cp := *log
	cp.Runs = make([]sarif.Run, len(log.Runs))
	for ri, run := range log.Runs {
		nr := run
		nr.Results = nil
		for _, r := range run.Results {
			fp := r.PartialFingerprints["trishul/v1"]
			if want[fp] > 0 {
				want[fp]--
				nr.Results = append(nr.Results, r)
			}
		}
		if nr.Results == nil {
			nr.Results = []sarif.Result{}
		}
		cp.Runs[ri] = nr
	}
	return &cp
}

// Counts tallies findings by severity.
func Counts(fs []Finding) map[string]int {
	c := map[string]int{}
	for _, f := range fs {
		c[f.Severity]++
	}
	return c
}

// Grade converts a set of findings into a letter grade for the badge.
func Grade(fs []Finding) string {
	c := Counts(fs)
	switch {
	case c["critical"] > 0:
		return "F"
	case c["high"] > 3:
		return "D"
	case c["high"] > 0:
		return "C"
	case c["medium"] > 5:
		return "B"
	default:
		return "A"
	}
}

// Summary is a one-line human summary of a severity tally.
func Summary(fs []Finding) string {
	if len(fs) == 0 {
		return "no issues"
	}
	c := Counts(fs)
	var parts []string
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		if c[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c[s], s))
		}
	}
	return strings.Join(parts, ", ")
}
