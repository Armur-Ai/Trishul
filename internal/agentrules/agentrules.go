// Package agentrules renders secure-coding guidance for AI coding tools from the
// rule catalog (plan D3): a stack-aware checklist written into CLAUDE.md,
// .cursor/rules, AGENTS.md, Copilot/Windsurf/Gemini instruction files, between
// stable markers so updates are idempotent. This is prevention — steering the
// agent away from the mistakes Trishul would otherwise flag.
package agentrules

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Armur-Ai/Trishul/internal/rules"
)

// Markers delimit the Trishul-managed section so `init rules` edits only it.
const (
	MarkerBegin = "<!-- trishul:begin -->"
	MarkerEnd   = "<!-- trishul:end -->"
)

// Tool is a target AI coding tool.
type Tool string

const (
	Claude   Tool = "claude"
	Cursor   Tool = "cursor"
	Agents   Tool = "agents"
	Copilot  Tool = "copilot"
	Windsurf Tool = "windsurf"
	Gemini   Tool = "gemini"
)

// FileFor returns the repo-relative path a tool's rules live in.
func FileFor(t Tool) string {
	switch t {
	case Claude:
		return "CLAUDE.md"
	case Cursor:
		return ".cursor/rules/trishul-security.mdc"
	case Agents:
		return "AGENTS.md"
	case Copilot:
		return ".github/copilot-instructions.md"
	case Windsurf:
		return ".windsurf/rules"
	case Gemini:
		return "GEMINI.md"
	default:
		return ""
	}
}

// stackFamilies maps a detected stack to the rule-id prefixes most relevant to
// it. Secrets and agent-supply-chain rules always apply.
var stackFamilies = map[string][]string{
	"nextjs":   {"VIBE-AUTHZ", "CLIENT-SECRET", "EXPLOIT-NEXTJS"},
	"supabase": {"SUPABASE-RLS", "CLIENT-SECRET"},
	"firebase": {"FIREBASE", "CLIENT-SECRET"},
	"express":  {"VIBE-AUTHZ", "VIBE-WEBHOOK"},
	"fastapi":  {"VIBE-AUTHZ"},
	"django":   {"VIBE-AUTHZ"},
	"rails":    {"VIBE-AUTHZ"},
	"go":       {"EXPLOIT-SPRING"},
}

var alwaysFamilies = []string{"AGENT-", "CLIENT-SECRET", "VIBE-LLM", "VIBE-PLACEHOLDER"}

// Stacks detects the frameworks a repo uses from its manifests (read-only).
func Stacks(root string) []string {
	found := map[string]bool{}
	add := func(s string) { found[s] = true }

	if b, err := os.ReadFile(filepath.Join(root, "package.json")); err == nil {
		s := string(b)
		if strings.Contains(s, "\"next\"") {
			add("nextjs")
		}
		if strings.Contains(s, "@supabase/") {
			add("supabase")
		}
		if strings.Contains(s, "firebase") {
			add("firebase")
		}
		if strings.Contains(s, "\"express\"") {
			add("express")
		}
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
		add("go")
	}
	for _, py := range []string{"requirements.txt", "pyproject.toml"} {
		if b, err := os.ReadFile(filepath.Join(root, py)); err == nil {
			s := strings.ToLower(string(b))
			if strings.Contains(s, "fastapi") {
				add("fastapi")
			}
			if strings.Contains(s, "django") {
				add("django")
			}
		}
	}
	if _, err := os.Stat(filepath.Join(root, "Gemfile")); err == nil {
		add("rails")
	}
	out := make([]string, 0, len(found))
	for s := range found {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// relevantRules returns the stable catalog rules relevant to the stacks, capped
// so the rendered file stays short, highest-severity first.
func relevantRules(cat *rules.Catalog, stacks []string, max int) []rules.RuleDef {
	want := map[string]bool{}
	for _, f := range alwaysFamilies {
		want[f] = true
	}
	for _, st := range stacks {
		for _, f := range stackFamilies[st] {
			want[f] = true
		}
	}
	var out []rules.RuleDef
	for _, d := range cat.All() {
		if d.Maturity != rules.MaturityStable {
			continue
		}
		for pref := range want {
			if strings.HasPrefix(d.ID, pref) {
				out = append(out, d)
				break
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return sevRank(out[i].DefaultSeverity) > sevRank(out[j].DefaultSeverity)
	})
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}

func sevRank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	}
	return 0
}

// Render produces the managed section body (no markers) for a tool, bounded to
// stay well under ~150 lines.
func Render(cat *rules.Catalog, stacks []string, _ Tool) string {
	var b strings.Builder
	b.WriteString("## Security rules (managed by Trishul)\n\n")
	b.WriteString("Follow these when writing or editing code in this repo. They mirror the checks Trishul enforces.\n\n")
	if len(stacks) > 0 {
		b.WriteString("Detected stack: " + strings.Join(stacks, ", ") + "\n\n")
	}
	for _, d := range relevantRules(cat, stacks, 40) {
		short := d.Short
		if short == "" {
			short = d.Title
		}
		b.WriteString("- **" + d.Title + "** (" + d.DefaultSeverity + "): " + short)
		if d.Fix != "" {
			b.WriteString(" → " + d.Fix)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// UpsertSection returns existing with the Trishul-managed section replaced (if
// the markers already exist) or appended (if not). The section body is wrapped
// in the markers. Idempotent: rendering the same body twice yields the same file.
func UpsertSection(existing, body string) string {
	block := MarkerBegin + "\n" + strings.TrimRight(body, "\n") + "\n" + MarkerEnd
	bi := strings.Index(existing, MarkerBegin)
	ei := strings.Index(existing, MarkerEnd)
	if bi >= 0 && ei > bi {
		return existing[:bi] + block + existing[ei+len(MarkerEnd):]
	}
	if existing == "" {
		return block + "\n"
	}
	return strings.TrimRight(existing, "\n") + "\n\n" + block + "\n"
}
