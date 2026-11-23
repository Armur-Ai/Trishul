// Package render turns a v2 finding (plus its rule metadata and source) into the
// markdown a reviewer reads (P4.1): a snippet with the offending line marked and
// secrets redacted, the evidence steps, and a "why this matters / how to fix"
// block linked to the rule's doc page. It is shared by the PR-comment and
// check-run renderers so both read identically.
package render

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Armur-Ai/Trishul/internal/findings"
	"github.com/Armur-Ai/Trishul/internal/redact"
	"github.com/Armur-Ai/Trishul/internal/rules"
)

// DocBaseURL is where per-rule docs are published.
const DocBaseURL = "https://armur.ai/trishul/rules"

var longToken = regexp.MustCompile(`[A-Za-z0-9_\-+/=]{16,}`)

// redactLine masks any long secret-like token in a line using the canonical
// redact.Mask, so a rendered snippet never exposes a real secret value.
func redactLine(line string) string {
	return longToken.ReplaceAllStringFunc(line, redact.Mask)
}

// MarkedSnippet renders the ±radius lines around a 1-based target line, each
// redacted, with the target line prefixed by "> " and line numbers shown.
func MarkedSnippet(src string, line, radius int) string {
	if radius < 0 {
		radius = 0
	}
	lines := strings.Split(src, "\n")
	lo, hi := line-1-radius, line-1+radius
	if lo < 0 {
		lo = 0
	}
	if hi >= len(lines) {
		hi = len(lines) - 1
	}
	if lo > hi || len(lines) == 0 {
		return ""
	}
	var b strings.Builder
	for i := lo; i <= hi; i++ {
		marker := "  "
		if i == line-1 {
			marker = "> "
		}
		fmt.Fprintf(&b, "%s%d  %s\n", marker, i+1, redactLine(lines[i]))
	}
	return b.String()
}

// DocURL returns the rule's documentation page URL.
func DocURL(ruleID string) string { return DocBaseURL + "/" + ruleID }

// Comment renders a full markdown block for one finding. def may be the zero
// RuleDef (not in catalog), in which case the why/how sections are omitted. src
// is the file content (may be empty — then the snippet is skipped).
func Comment(f findings.Finding, def rules.RuleDef, src string) string {
	var b strings.Builder

	title := def.Title
	if title == "" {
		title = f.Title
	}
	if title == "" {
		title = f.RuleID
	}
	fmt.Fprintf(&b, "**%s** — %s / %s confidence\n\n", title, f.Severity, f.Band)
	if f.Message != "" {
		fmt.Fprintf(&b, "%s\n\n", f.Message)
	}

	if src != "" && f.Location.StartLine > 0 {
		snip := MarkedSnippet(src, f.Location.StartLine, 3)
		if snip != "" {
			fmt.Fprintf(&b, "```\n%s```\n\n", snip)
		}
	}

	if len(f.Evidence) > 0 {
		b.WriteString("Evidence:\n")
		for _, e := range f.Evidence {
			if e.Path != "" && e.Line > 0 {
				fmt.Fprintf(&b, "- `%s:%d` — %s\n", e.Path, e.Line, e.Note)
			} else {
				fmt.Fprintf(&b, "- %s\n", e.Note)
			}
		}
		b.WriteString("\n")
	}

	if def.Description != "" {
		fmt.Fprintf(&b, "**Why it matters:** %s\n\n", firstSentence(def.Description))
	}
	fix := def.Fix
	if fix == "" {
		fix = f.Remediation.Text
	}
	if fix != "" {
		fmt.Fprintf(&b, "**How to fix:** %s\n\n", fix)
	}
	fmt.Fprintf(&b, "[%s docs](%s)\n", f.RuleID, DocURL(f.RuleID))
	return b.String()
}

// firstSentence returns the first sentence of s (up to the first period followed
// by a space or end), so the "why it matters" line stays short.
func firstSentence(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if i := strings.Index(s, ". "); i >= 0 {
		return s[:i+1]
	}
	return s
}
