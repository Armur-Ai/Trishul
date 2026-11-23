package agenthook

import (
	"fmt"
	"strings"
)

// renderFindings formats findings as indented, human- and agent-readable lines:
//
//	[HIGH] RULE-ID  path:line
//	    why: <message>
//	    fix: <fix>
func renderFindings(fs []Finding) string {
	var b strings.Builder
	for _, f := range fs {
		loc := f.Path
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.Path, f.Line)
		}
		fmt.Fprintf(&b, "  [%s] %s  %s\n", strings.ToUpper(f.Severity), f.RuleID, loc)
		if f.Message != "" {
			fmt.Fprintf(&b, "    why: %s\n", f.Message)
		}
		if f.Fix != "" {
			fmt.Fprintf(&b, "    fix: %s\n", f.Fix)
		}
	}
	return b.String()
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// blockMessage is the stderr shown when an edit introduces blocking findings.
func blockMessage(fs []Finding, blockOn string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Trishul blocked this edit: %d new issue%s at or above %q.\n\n",
		len(fs), plural(len(fs)), blockOn)
	b.WriteString(renderFindings(fs))
	b.WriteString("\nResolve the issue")
	b.WriteString(plural(len(fs)))
	b.WriteString(", or add a reviewed inline suppression (e.g. trishul-ignore[RULE-ID]: reason).\n")
	return b.String()
}

// warnMessage is the stderr shown for non-blocking findings (loop-breaker
// downgrades). The hook still exits 0.
func warnMessage(fs []Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Trishul warning: %d issue%s re-reported repeatedly — downgraded to a warning (loop breaker).\n\n",
		len(fs), plural(len(fs)))
	b.WriteString(renderFindings(fs))
	return b.String()
}

// bashBlockMessage / bashWarnMessage describe dangerous Bash commands.
func bashBlockMessage(fs []Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Trishul blocked this command: %d dangerous execution path%s detected.\n\n",
		len(fs), plural(len(fs)))
	b.WriteString(renderFindings(fs))
	return b.String()
}

func bashWarnMessage(fs []Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Trishul warning: %d dangerous execution path%s in this command (allowed by bash_guard=warn).\n\n",
		len(fs), plural(len(fs)))
	b.WriteString(renderFindings(fs))
	return b.String()
}

// summaryMessage is printed on a Stop / SessionEnd event.
func summaryMessage(edits, blocked int) string {
	return fmt.Sprintf("Trishul checked %d edit%s, blocked %d issue%s\n",
		edits, plural(edits), blocked, plural(blocked))
}
