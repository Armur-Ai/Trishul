// Package sharecard renders a small, shareable SVG "grade card" for an audit
// result (plan D4.3): a grade letter and severity counts a user can post, with
// NO paths, secrets, repo names or any identifying content — only aggregate
// numbers. Rendering is fully local; nothing is uploaded.
package sharecard

import (
	"fmt"
	"html"
	"sort"
	"strings"
)

// Card holds the only data allowed on the card: a title, a grade, and counts.
type Card struct {
	Title  string         // e.g. "My AI setup" — caller must not put a path/secret here
	Grade  string         // A–F
	Counts map[string]int // severity -> count (CRITICAL/HIGH/MEDIUM/LOW)
}

var gradeColor = map[string]string{
	"A": "#22c55e", "B": "#84cc16", "C": "#eab308", "D": "#f97316", "F": "#ef4444",
}

var sevOrder = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}

// SVG renders the card as a self-contained SVG string. All dynamic text is
// HTML-escaped. Only the title, grade letter and integer counts appear.
func (c Card) SVG() string {
	color := gradeColor[strings.ToUpper(c.Grade)]
	if color == "" {
		color = "#64748b"
	}
	title := html.EscapeString(sanitizeTitle(c.Title))

	var rows strings.Builder
	y := 92
	for _, sev := range sevOrder {
		n := c.Counts[sev]
		if n == 0 {
			continue
		}
		fmt.Fprintf(&rows, `<text x="30" y="%d" fill="#cbd5e1" font-size="15">%s</text>`+
			`<text x="330" y="%d" fill="#f1f5f9" font-size="15" text-anchor="end">%d</text>`,
			y, title2(sev), y, n)
		y += 26
	}

	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="360" height="%d" viewBox="0 0 360 %d" role="img">
<rect width="360" height="%d" rx="12" fill="#0f172a"/>
<text x="30" y="40" fill="#f1f5f9" font-size="18" font-weight="700">%s</text>
<text x="30" y="62" fill="#64748b" font-size="12">Trishul AI-setup audit</text>
<circle cx="310" cy="44" r="26" fill="%s"/>
<text x="310" y="52" fill="#0f172a" font-size="26" font-weight="800" text-anchor="middle">%s</text>
%s
</svg>`, y+10, y+10, y+10, title, color, html.EscapeString(strings.ToUpper(c.Grade)), rows.String())
}

// sanitizeTitle strips anything that looks like a path or secret from the title,
// so a careless caller can't leak one onto a shareable card.
func sanitizeTitle(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return "My AI setup"
	}
	// Drop path-like and secret-like tokens.
	fields := strings.Fields(t)
	kept := fields[:0]
	for _, f := range fields {
		if strings.ContainsAny(f, "/\\") || len(f) >= 20 {
			continue
		}
		kept = append(kept, f)
	}
	out := strings.Join(kept, " ")
	if out == "" {
		return "My AI setup"
	}
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}

func title2(sev string) string {
	s := strings.ToLower(sev)
	return strings.ToUpper(s[:1]) + s[1:]
}

// CountsFromSeverities tallies a severity slice into a counts map.
func CountsFromSeverities(sevs []string) map[string]int {
	m := map[string]int{}
	for _, s := range sevs {
		m[strings.ToUpper(s)]++
	}
	return m
}

// Severities returns the severity keys present, in canonical order (for tests).
func Severities(m map[string]int) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
