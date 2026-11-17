package models

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// Severity represents the severity level of a finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Finding represents a single security finding from any tool.
type Finding struct {
	ID          string   `json:"id"`
	Tool        string   `json:"tool"`
	Source      string   `json:"source,omitempty"`       // sast | dast | sca | secrets | iac | exploit | attack_path
	Category    string   `json:"category"`               // security_issues | antipatterns_bugs | complex_functions | etc.
	File        string   `json:"file"`
	Line        int      `json:"line"`
	EndLine     int      `json:"end_line,omitempty"`
	Column      int      `json:"column,omitempty"`
	RuleID      string   `json:"rule_id,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	OWASP       string   `json:"owasp,omitempty"`
	Severity    Severity `json:"severity"`
	Confidence  string   `json:"confidence,omitempty"`   // high | medium | low
	Message     string   `json:"message"`
	Snippet     string   `json:"snippet,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Confirmed   bool     `json:"confirmed,omitempty"`    // true when DAST or exploit simulation verified
	DuplicateOf []string `json:"duplicate_of,omitempty"` // IDs of findings this is a duplicate of
}

// fingerprintBasis returns the stable, line-insensitive tuple used to identify
// a finding: Tool | File | RuleID | normalized-Message. The raw line number is
// deliberately excluded (see ComputeID) and so is any field — such as Snippet
// or Column — that moves with surrounding edits.
func (f *Finding) fingerprintBasis() string {
	return f.Tool + "|" + f.File + "|" + f.RuleID + "|" + normalizeMessage(f.Message)
}

// normalizeMessage canonicalizes a finding message so cosmetic differences
// (surrounding/duplicate whitespace, letter case) don't change the fingerprint.
// It collapses runs of whitespace to single spaces, lowercases, and truncates
// to 64 runes to stay stable against long, variable tails.
func normalizeMessage(msg string) string {
	normalized := strings.ToLower(strings.Join(strings.Fields(msg), " "))
	if r := []rune(normalized); len(r) > 64 {
		return string(r[:64])
	}
	return normalized
}

// ComputeID generates a stable SHA256 fingerprint for the finding.
//
// The identity is derived from a semantic location — Tool | File | RuleID |
// normalized-Message — and intentionally EXCLUDES the raw line number. Line
// numbers churn whenever unrelated edits above a finding shift it up or down,
// which would otherwise give the "same" issue a brand-new ID on every such
// edit (breaking dedup, suppression, and cross-scan tracking). The line is
// still reported on the Finding; it simply isn't part of its identity. The
// result is the same 32-char hex string (first 16 bytes of the digest) as the
// prior line-sensitive scheme.
func (f *Finding) ComputeID() {
	hash := sha256.Sum256([]byte(f.fingerprintBasis()))
	f.ID = fmt.Sprintf("%x", hash[:16]) // 32-char hex string
}

// ScanResult represents the complete output of a scan.
type ScanResult struct {
	TaskID    string        `json:"task_id"`
	Status    string        `json:"status"` // success | failed | cancelled
	Findings  []Finding     `json:"findings"`
	Errors    []ScanError   `json:"errors,omitempty"`
	Meta      ScanMeta      `json:"meta"`
	DedupMeta *DedupMeta    `json:"dedup,omitempty"`
}

// ScanError captures a tool-level failure that occurred during a scan.
type ScanError struct {
	Tool    string `json:"tool"`
	Message string `json:"message"`
}

// ScanMeta holds metadata about the scan execution.
type ScanMeta struct {
	Language  string   `json:"language"`
	Mode      string   `json:"mode"` // simple | advanced
	ToolsRun  []string `json:"tools_run"`
	Duration  float64  `json:"duration_secs"`
	FileCount int      `json:"file_count,omitempty"`
}

// DedupMeta holds deduplication statistics.
type DedupMeta struct {
	RawCount     int `json:"raw_count"`
	AfterDedup   int `json:"after_dedup"`
	DupesRemoved int `json:"dupes_removed"`
}

// SeverityOrder returns a numeric value for severity comparison.
func SeverityOrder(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}
