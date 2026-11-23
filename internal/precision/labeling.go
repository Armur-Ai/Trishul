package precision

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Labeling helpers (P0.4). The interactive labeler is a thin terminal layer over
// these: it shows a finding with redacted context and appends a verdict. Keeping
// the core here makes it testable and reusable (e.g. scripted labeling).

// AppendLabel writes one label as a JSONL line. Callers open the labels file in
// append mode and pass the writer.
func AppendLabel(w io.Writer, l Label) error {
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}

// secretish matches long unbroken token runs that are likely secrets/keys.
var secretish = regexp.MustCompile(`[A-Za-z0-9_\-+/=]{16,}`)

// Redact masks likely secret values in a line so they never reach a label or the
// labeler's screen: a long token keeps its first 3 and last 2 characters and
// shows its length, e.g. "AKIA…(20)…7Q". Shorter tokens are left alone.
func Redact(line string) string {
	return secretish.ReplaceAllStringFunc(line, func(tok string) string {
		if len(tok) < 16 {
			return tok
		}
		return tok[:3] + "…(" + itoa(len(tok)) + ")…" + tok[len(tok)-2:]
	})
}

// Context returns the ±radius lines around a 1-based target line, each redacted,
// with the target line marked by a leading ">". Used by the labeler to show a
// finding without leaking secret values.
func Context(src string, line, radius int) string {
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
	var b strings.Builder
	for i := lo; i <= hi; i++ {
		marker := "  "
		if i == line-1 {
			marker = "> "
		}
		fmt.Fprintf(&b, "%s%d: %s\n", marker, i+1, Redact(lines[i]))
	}
	return b.String()
}

// ValidVerdict reports whether s is one of the four verdict strings.
func ValidVerdict(s string) bool {
	switch Verdict(s) {
	case TP, TPBenign, FP, Unclear:
		return true
	}
	return false
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
