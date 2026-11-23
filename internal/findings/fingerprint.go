package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// FingerprintV2 computes a stable, message-independent identity for a finding:
//
//	sha256( rule_id | path | normalized_snippet_window )
//
// The normalized window is the finding's snippet with whitespace collapsed and
// literals masked, so the identity survives reworded messages, reformatting,
// and edits to surrounding lines. Two genuinely different occurrences in the
// same file keep distinct fingerprints because their snippet windows differ.
//
// When the snippet is empty the fingerprint falls back to rule_id|path, which
// is coarser but still stable; analyzers should pass a ±2-line snippet window
// so distinct occurrences separate cleanly.
func FingerprintV2(ruleID, path, snippet string) string {
	norm := NormalizeWindow(snippet)
	h := sha256.Sum256([]byte(ruleID + "\x00" + path + "\x00" + norm))
	return hex.EncodeToString(h[:16])
}

var (
	// Double- or single-quoted string literals (non-greedy, escaped-quote aware).
	reStringLit = regexp.MustCompile(`"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`)
	// Backtick / template literals.
	reRawLit = regexp.MustCompile("`(?:[^`\\\\]|\\\\.)*`")
	// Numeric literals (ints, floats, hex).
	reNumLit = regexp.MustCompile(`\b0[xX][0-9a-fA-F]+\b|\b\d+(?:\.\d+)?\b`)
	// Runs of whitespace.
	reWS = regexp.MustCompile(`\s+`)
)

// NormalizeWindow canonicalizes a snippet so cosmetic differences don't change
// a fingerprint: string, raw and numeric literals are masked to fixed tokens
// and all whitespace is removed. Dropping whitespace entirely (rather than
// collapsing runs to a single space) makes the identity robust to reformatting
// such as spaces added inside parentheses or around operators.
//
// Masking literals is deliberate — a secret's value, a port number or a URL can
// change between occurrences of the same structural issue; the structure is
// what identifies the finding.
func NormalizeWindow(snippet string) string {
	if snippet == "" {
		return ""
	}
	s := reRawLit.ReplaceAllString(snippet, "`S`")
	s = reStringLit.ReplaceAllString(s, `"S"`)
	s = reNumLit.ReplaceAllString(s, "N")
	return reWS.ReplaceAllString(s, "")
}

// Window extracts the ±radius lines around a 1-based target line from src,
// suitable for passing to FingerprintV2 and for the finding snippet. Lines out
// of range are skipped; radius < 0 is treated as 0.
func Window(src string, line, radius int) string {
	if radius < 0 {
		radius = 0
	}
	lines := strings.Split(src, "\n")
	lo := line - 1 - radius
	hi := line - 1 + radius
	if lo < 0 {
		lo = 0
	}
	if hi >= len(lines) {
		hi = len(lines) - 1
	}
	if lo > hi {
		return ""
	}
	return strings.Join(lines[lo:hi+1], "\n")
}
