package agenthook

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// Finding is one normalized issue produced by a single-file scan. It carries
// everything the stderr contract needs: the rule, the line, the "why"
// (Message) and a "fix" hint.
type Finding struct {
	RuleID      string
	Severity    string // info|low|medium|high|critical (lower-cased)
	Path        string
	Line        int
	Message     string // why this is a problem
	Fix         string // how to address it
	Fingerprint string // stable, line-insensitive identity
}

// fingerprint returns f.Fingerprint, computing a stable one (rule|path|message,
// deliberately line-insensitive) when the scanner did not supply it.
func (f Finding) fingerprint() string {
	if f.Fingerprint != "" {
		return f.Fingerprint
	}
	sum := sha256.Sum256([]byte(f.RuleID + "|" + f.Path + "|" + f.Message))
	return hex.EncodeToString(sum[:])[:16]
}

var severityRank = map[string]int{
	"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}

// rank returns the numeric order of a severity (info=0 … critical=4). An
// unknown value ranks as medium, matching internal/prgate.
func rank(sev string) int {
	if r, ok := severityRank[strings.ToLower(strings.TrimSpace(sev))]; ok {
		return r
	}
	return 2
}

// sortFindings orders findings by severity (desc), then path, line, rule — a
// deterministic order for stable stderr output.
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if rank(a.Severity) != rank(b.Severity) {
			return rank(a.Severity) > rank(b.Severity)
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

// fingerprintSet collects the fingerprints of a finding slice.
func fingerprintSet(fs []Finding) map[string]int {
	m := make(map[string]int, len(fs))
	for _, f := range fs {
		m[f.fingerprint()]++
	}
	return m
}
