package prgate

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// CommentMarker identifies Trishul's PR comment so it is edited in place on
// every push instead of posting a new one.
const CommentMarker = "<!-- trishul-pr-gate -->"

// ProjectURL is linked from every comment and check run.
const ProjectURL = "https://github.com/Armur-Ai/Trishul"

// Report is the outcome of a PR (or full-tree) scan.
type Report struct {
	// Mode is "pr" (diffed against a base) or "full".
	Mode string `json:"mode"`
	// New are findings the PR introduced (mode "pr") or all non-baselined
	// findings (mode "full").
	New []Finding `json:"new"`
	// Fixed are base findings no longer present in head (mode "pr" only).
	Fixed []Finding `json:"fixed"`
	// Existing counts pre-existing findings that were not reported.
	Existing int `json:"existing"`
	// Total is the number of findings in the head tree.
	Total int `json:"total"`
	// FailOn is the severity threshold that fails the gate ("" = never).
	FailOn string `json:"fail_on,omitempty"`
	// Failed is true when New contains a finding at or above FailOn.
	Failed   bool          `json:"failed"`
	Duration time.Duration `json:"duration_ns"`
	// LinkBase, when set (https://github.com/o/r/blob/<sha>/), turns
	// locations into links.
	LinkBase string `json:"-"`
	// ScanErrors are analyzer failures (non-fatal).
	ScanErrors []string `json:"scan_errors,omitempty"`
}

// Evaluate sets Failed from FailOn.
func (r *Report) Evaluate() {
	r.Failed = r.FailOn != "" && len(AtOrAbove(r.New, r.FailOn)) > 0
}

// Title is a short status line (used for the check-run title).
func (r *Report) Title() string {
	n := len(r.New)
	scope := "in this PR"
	if r.Mode == "full" {
		scope = "found"
	}
	if n == 0 {
		if r.Mode == "full" {
			return "No issues found"
		}
		return "No new issues"
	}
	noun := "issue"
	if n != 1 {
		noun = "issues"
	}
	if r.Mode == "full" {
		return fmt.Sprintf("%d %s %s (%s)", n, noun, scope, Summary(r.New))
	}
	return fmt.Sprintf("%d new %s %s (%s)", n, noun, scope, Summary(r.New))
}

var sevIcon = map[string]string{
	"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪",
}

// maxRows caps the findings table so a noisy PR doesn't produce a wall.
const maxRows = 25

// Markdown renders the PR comment / step summary.
func (r *Report) Markdown() string {
	var b strings.Builder
	b.WriteString(CommentMarker + "\n")
	if len(r.New) == 0 {
		b.WriteString("### 🔱 Trishul: " + r.Title() + " ✅\n\n")
		if r.Mode == "pr" {
			b.WriteString("This PR doesn't introduce any security issues Trishul checks for")
			b.WriteString(" (AI-agent supply chain, Vibe Top 10, secrets, exposed data rules).\n")
		}
	} else {
		status := ""
		if r.Failed {
			status = " ❌"
		}
		b.WriteString("### 🔱 Trishul: " + r.Title() + status + "\n\n")
		b.WriteString("| | Severity | Rule | Location | Issue |\n|---|---|---|---|---|\n")
		for i, f := range r.New {
			if i == maxRows {
				break
			}
			fmt.Fprintf(&b, "| %s | %s | `%s` | %s | %s |\n",
				sevIcon[f.Severity], f.Severity, f.RuleID, r.location(f), cell(f.Message, 220))
		}
		if len(r.New) > maxRows {
			fmt.Fprintf(&b, "\n…and %d more. See the **Trishul** check run or the Security tab for the full list.\n", len(r.New)-maxRows)
		}
		b.WriteString("\n<details><summary>Not a real issue?</summary>\n\n")
		b.WriteString("Add the finding's fingerprint to `" + DefaultBaselineFile + "` (generate one with `trishul-ci --write-baseline`), ")
		b.WriteString("or disable an analyzer in `.trishul.yml`. Accepted findings stop being reported on future PRs.\n\n</details>\n")
	}
	if len(r.Fixed) > 0 {
		fmt.Fprintf(&b, "\n🎉 This PR fixes %d existing issue(s).\n", len(r.Fixed))
	}
	var foot []string
	if r.Mode == "pr" && r.Existing > 0 {
		foot = append(foot, fmt.Sprintf("%d pre-existing issue(s) not shown", r.Existing))
	}
	if r.Duration > 0 {
		foot = append(foot, fmt.Sprintf("scanned in %.1fs", r.Duration.Seconds()))
	}
	if r.FailOn == "" && len(r.New) > 0 {
		foot = append(foot, "non-blocking")
	}
	foot = append(foot, "[Trishul]("+ProjectURL+"): security for AI-written code")
	b.WriteString("\n<sub>" + strings.Join(foot, " · ") + "</sub>\n")
	return b.String()
}

func (r *Report) location(f Finding) string {
	loc := f.Path
	if f.Line > 0 {
		loc = fmt.Sprintf("%s:%d", f.Path, f.Line)
	}
	if loc == "" {
		return "n/a"
	}
	if r.LinkBase != "" && f.Path != "" {
		anchor := ""
		if f.Line > 0 {
			anchor = fmt.Sprintf("#L%d", f.Line)
		}
		return fmt.Sprintf("[`%s`](%s%s%s)", cell(loc, 80), r.LinkBase, escapePath(f.Path), anchor)
	}
	return "`" + cell(loc, 80) + "`"
}

// cell makes text safe for a single markdown table cell.
func cell(s string, max int) string {
	s = strings.NewReplacer("\r", " ", "\n", " ", "|", "\\|", "<", "&lt;", ">", "&gt;", "`", "'", "@", "@\u200b", "[", "\\[", "]", "\\]").Replace(s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > max {
		s = string(r[:max-1]) + "…"
	}
	return s
}

// escapePath URL-escapes each path segment for use in a blob link.
func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}
