// Package suppress parses inline suppression markers from source files and
// decides whether a finding at a given location is suppressed (P2.3).
//
// Trishul's own marker requires a reason:
//
//	trishul-ignore[RULE-ID]: we accept this, tracked in TICKET-123
//	trishul-ignore: blanket reason        (applies to every rule on the line)
//
// A marker with no reason does NOT suppress — silent ignores are exactly the
// thing a reviewer needs to see. For interop, bare third-party markers are also
// honored: nosec, nosemgrep and gitleaks:allow (each optionally naming a rule).
//
// A marker on line N suppresses matching findings on line N and line N+1 (the
// "same line or the line above" rule), so a comment can sit above the code.
package suppress

import (
	"regexp"
	"strconv"
	"strings"
)

// Marker names the suppression syntax that matched.
type Marker string

const (
	MarkerTrishul   Marker = "trishul-ignore"
	MarkerNosec     Marker = "nosec"
	MarkerNosemgrep Marker = "nosemgrep"
	MarkerGitleaks  Marker = "gitleaks:allow"
)

// Suppression is one parsed marker.
type Suppression struct {
	Path   string
	Line   int // the line the marker is on (1-based)
	Marker Marker
	RuleID string // specific rule, or "" for wildcard (all rules on the line)
	Reason string

	idx int // position in the originating slice; set by NewIndex for match tracking
}

// Wildcard reports whether this suppression applies to any rule.
func (s Suppression) Wildcard() bool { return s.RuleID == "" }

var (
	reTrishul   = regexp.MustCompile(`trishul-ignore(?:\[([A-Za-z0-9*._-]+)\])?\s*:\s*(.+?)\s*$`)
	reNosec     = regexp.MustCompile(`\bnosec\b(?:\s+([A-Za-z0-9,._-]+))?`)
	reNosemgrep = regexp.MustCompile(`\bnosemgrep\b(?:\s*:\s*([A-Za-z0-9,._-]+))?`)
	reGitleaks  = regexp.MustCompile(`gitleaks:allow`)
)

// ScanFile parses all suppression markers in content. Line numbers are 1-based.
func ScanFile(path string, content []byte) []Suppression {
	var out []Suppression
	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		ln := i + 1
		if m := reTrishul.FindStringSubmatch(line); m != nil {
			rule := m[1]
			if rule == "*" {
				rule = ""
			}
			reason := strings.TrimSpace(m[2])
			if reason == "" {
				continue // reason required
			}
			out = append(out, Suppression{Path: path, Line: ln, Marker: MarkerTrishul, RuleID: rule, Reason: reason})
			continue
		}
		if m := reNosec.FindStringSubmatch(line); m != nil {
			out = append(out, expand(path, ln, MarkerNosec, m[1])...)
		}
		if m := reNosemgrep.FindStringSubmatch(line); m != nil {
			out = append(out, expand(path, ln, MarkerNosemgrep, m[1])...)
		}
		if reGitleaks.MatchString(line) {
			out = append(out, Suppression{Path: path, Line: ln, Marker: MarkerGitleaks})
		}
	}
	return out
}

// expand turns an optional comma-separated rule list into one suppression per
// rule (or a single wildcard when the list is empty).
func expand(path string, line int, marker Marker, ruleList string) []Suppression {
	ruleList = strings.TrimSpace(ruleList)
	if ruleList == "" {
		return []Suppression{{Path: path, Line: line, Marker: marker}}
	}
	var out []Suppression
	for _, r := range strings.Split(ruleList, ",") {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, Suppression{Path: path, Line: line, Marker: marker, RuleID: r})
		}
	}
	return out
}

// Index answers suppression queries efficiently, keyed by path then line.
type Index struct {
	byPathLine map[string][]Suppression // key "path\x00line"
	used       map[int]bool             // positions in all that matched a finding
	all        []Suppression
}

// NewIndex builds a queryable index from parsed suppressions.
func NewIndex(supps []Suppression) *Index {
	ix := &Index{byPathLine: map[string][]Suppression{}, used: map[int]bool{}, all: supps}
	for i, s := range supps {
		s.idx = i
		ix.byPathLine[key(s.Path, s.Line)] = append(ix.byPathLine[key(s.Path, s.Line)], s)
	}
	return ix
}

// Suppressed reports whether a finding of ruleID at (path, line) is suppressed,
// returning the matching suppression. It checks the finding's own line and the
// line above (a marker on line N covers N and N+1). A match is recorded so
// Unused can report markers that never suppressed anything.
func (ix *Index) Suppressed(path string, line int, ruleID string) (Suppression, bool) {
	// A marker on line N covers findings on N (probe=line) and N+1 (probe=line-1).
	for _, probe := range []int{line, line - 1} {
		for _, s := range ix.byPathLine[key(path, probe)] {
			if s.matches(ruleID) {
				ix.used[s.idx] = true
				return s, true
			}
		}
	}
	return Suppression{}, false
}

// Unused returns suppressions that never matched a finding (dead ignores worth
// surfacing or cleaning up).
func (ix *Index) Unused() []Suppression {
	var out []Suppression
	for i, s := range ix.all {
		if !ix.used[i] {
			out = append(out, s)
		}
	}
	return out
}

func (s Suppression) matches(ruleID string) bool {
	return s.Wildcard() || strings.EqualFold(s.RuleID, ruleID)
}

func key(path string, line int) string {
	return path + "\x00" + strconv.Itoa(line)
}
