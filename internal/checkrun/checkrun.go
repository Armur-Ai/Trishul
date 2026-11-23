// Package checkrun renders the GitHub check-run summary for a gate result
// (plan P5.1): a headline, severity/category counts, findings grouped by
// category with evidence, a fixed list, a suppressed list, and a footer —
// truncated to GitHub's 65,535-character limit with the headline and top
// findings preserved.
package checkrun

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Armur-Ai/Trishul/internal/findings"
	"github.com/Armur-Ai/Trishul/internal/render"
	"github.com/Armur-Ai/Trishul/internal/rules"
)

// MaxBody is GitHub's check-run summary character limit.
const MaxBody = 65535

// SuppressInfo is a suppressed finding, for the "suppressed in this PR" list.
type SuppressInfo struct {
	RuleID string
	Path   string
	Line   int
	Reason string
}

// Input is everything the renderer needs.
type Input struct {
	New        []findings.Finding // surfaced new findings (inline + summary), priority order
	Overflow   []findings.Finding // beyond the comment budget
	Fixed      []findings.Finding // present in base, gone in head
	Suppressed []SuppressInfo
	Blocked    bool
	Version    string
	Duration   time.Duration
	Catalog    *rules.Catalog
	// SrcFor returns a file's content for snippet rendering (may be nil).
	SrcFor func(path string) string
}

// Render produces the check-run markdown body.
func Render(in Input) string {
	var b strings.Builder
	b.WriteString(headline(in))
	b.WriteString("\n\n")
	b.WriteString(counts(in.New))

	// Findings grouped by category (then priority within category).
	if len(in.New) > 0 {
		b.WriteString("\n## New findings\n\n")
		b.WriteString(groupedFindings(in))
	}
	if len(in.Overflow) > 0 {
		fmt.Fprintf(&b, "\n_+%d more below the comment budget (see the SARIF artifact)._\n", len(in.Overflow))
	}
	if len(in.Fixed) > 0 {
		fmt.Fprintf(&b, "\n## Fixed (%d)\n\n", len(in.Fixed))
		for _, f := range in.Fixed {
			fmt.Fprintf(&b, "- ~~%s~~ `%s:%d`\n", f.RuleID, f.Location.Path, f.Location.StartLine)
		}
	}
	if len(in.Suppressed) > 0 {
		fmt.Fprintf(&b, "\n## Suppressed in this PR (%d)\n\n", len(in.Suppressed))
		for _, s := range in.Suppressed {
			fmt.Fprintf(&b, "- `%s` %s:%d — %s\n", s.RuleID, s.Path, s.Line, s.Reason)
		}
	}
	fmt.Fprintf(&b, "\n---\nTrishul %s · %s\n", versionOr(in.Version), in.Duration.Round(time.Millisecond))

	return truncate(b.String())
}

func headline(in Input) string {
	if len(in.New) == 0 {
		return "## No new issues ✅"
	}
	var crit, high int
	for _, f := range in.New {
		switch f.Severity {
		case findings.SeverityCritical:
			crit++
		case findings.SeverityHigh:
			high++
		}
	}
	gate := "gate passed"
	if in.Blocked {
		gate = "gate failed"
	}
	return fmt.Sprintf("## %d new issue%s (%d critical, %d high) · %s",
		len(in.New), plural(len(in.New)), crit, high, gate)
}

func counts(fs []findings.Finding) string {
	if len(fs) == 0 {
		return ""
	}
	bySev := map[findings.Severity]int{}
	byCat := map[string]int{}
	for _, f := range fs {
		bySev[f.Severity]++
		cat := f.Category
		if cat == "" {
			cat = "other"
		}
		byCat[cat]++
	}
	var b strings.Builder
	b.WriteString("| Severity | Count |\n|---|---|\n")
	for _, s := range []findings.Severity{findings.SeverityCritical, findings.SeverityHigh, findings.SeverityMedium, findings.SeverityLow, findings.SeverityInfo} {
		if bySev[s] > 0 {
			fmt.Fprintf(&b, "| %s | %d |\n", s, bySev[s])
		}
	}
	return b.String()
}

func groupedFindings(in Input) string {
	byCat := map[string][]findings.Finding{}
	var cats []string
	for _, f := range in.New {
		cat := f.Category
		if cat == "" {
			cat = "other"
		}
		if _, ok := byCat[cat]; !ok {
			cats = append(cats, cat)
		}
		byCat[cat] = append(byCat[cat], f)
	}
	sort.Strings(cats)
	var b strings.Builder
	for _, cat := range cats {
		fmt.Fprintf(&b, "### %s\n\n", cat)
		for _, f := range byCat[cat] {
			var def rules.RuleDef
			if in.Catalog != nil {
				def, _ = in.Catalog.Get(f.RuleID)
			}
			src := ""
			if in.SrcFor != nil {
				src = in.SrcFor(f.Location.Path)
			}
			b.WriteString(render.Comment(f, def, src))
			b.WriteString("\n")
		}
	}
	return b.String()
}

// truncate keeps the body within MaxBody, cutting at a line boundary and adding
// a notice.
func truncate(s string) string {
	if len(s) <= MaxBody {
		return s
	}
	const notice = "\n\n_…output truncated; see the full SARIF artifact._\n"
	cut := MaxBody - len(notice)
	if nl := strings.LastIndexByte(s[:cut], '\n'); nl > 0 {
		cut = nl
	}
	return s[:cut] + notice
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func versionOr(v string) string {
	if v == "" {
		return "dev"
	}
	return v
}
