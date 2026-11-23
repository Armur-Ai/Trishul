// Command trishul-rulesdoc turns the rule catalog into per-rule markdown docs
// plus an index (P1.2).
//
//	trishul-rulesdoc --rules rules --out docs/rules
//
// It loads the catalog from --rules, validates it, writes one <ID>.md per rule
// and a README.md index table into --out. Output is deterministic: rules are
// emitted in sorted-ID order and no timestamps are written.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Armur-Ai/Trishul/internal/rules"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "trishul-rulesdoc:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("trishul-rulesdoc", flag.ContinueOnError)
	rulesDir := fs.String("rules", "rules", "directory holding the rule catalog yaml files")
	outDir := fs.String("out", "docs/rules", "directory to write the generated markdown into")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cat, err := rules.LoadCatalog(*rulesDir)
	if err != nil {
		return err
	}
	if verrs := cat.Validate(); len(verrs) > 0 {
		var b strings.Builder
		b.WriteString(fmt.Sprintf("catalog has %d validation error(s):", len(verrs)))
		for _, e := range verrs {
			b.WriteString("\n  - " + e.Error())
		}
		return fmt.Errorf("%s", b.String())
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return fmt.Errorf("create out dir: %w", err)
	}

	defs := cat.All()
	for _, d := range defs {
		md := renderRule(d)
		path := filepath.Join(*outDir, d.ID+".md")
		if err := os.WriteFile(path, []byte(md), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}

	readme := renderIndex(defs)
	readmePath := filepath.Join(*outDir, "README.md")
	if err := os.WriteFile(readmePath, []byte(readme), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", readmePath, err)
	}

	fmt.Printf("wrote %d rule docs + index to %s\n", len(defs), *outDir)
	return nil
}

// renderRule renders a single rule as markdown.
func renderRule(d rules.RuleDef) string {
	var b strings.Builder

	title := d.Title
	if title == "" {
		title = d.ID
	}
	b.WriteString("# " + d.ID + ": " + title + "\n\n")

	if short := strings.TrimSpace(d.Short); short != "" {
		b.WriteString(short + "\n\n")
	}

	b.WriteString("## Metadata\n\n")
	b.WriteString("| Field | Value |\n")
	b.WriteString("| --- | --- |\n")
	b.WriteString(metaRow("Severity", d.DefaultSeverity))
	b.WriteString(metaRow("Confidence", fmt.Sprintf("%.2f", d.DefaultConfidence)))
	b.WriteString(metaRow("Maturity", string(d.Maturity)))
	b.WriteString(metaRow("Mode", string(d.ModeDefault)))
	b.WriteString(metaRow("Languages", joinOrDash(d.Languages)))
	b.WriteString(metaRow("File kinds", joinOrDash(d.FileKinds)))
	b.WriteString(metaRow("CWE", joinOrDash(d.CWE)))
	b.WriteString(metaRow("OWASP", joinOrDash(d.OWASP)))
	b.WriteString("\n")

	if desc := strings.TrimSpace(d.Description); desc != "" {
		b.WriteString("## Description\n\n")
		b.WriteString(desc + "\n\n")
	}

	if fix := strings.TrimSpace(d.Fix); fix != "" {
		b.WriteString("## Fix\n\n")
		b.WriteString(fix + "\n\n")
	}

	bad := strings.TrimRight(d.Examples.Bad, "\n")
	good := strings.TrimRight(d.Examples.Good, "\n")
	if bad != "" || good != "" {
		b.WriteString("## Examples\n\n")
		if bad != "" {
			b.WriteString("Bad:\n\n")
			b.WriteString("```bad\n" + bad + "\n```\n\n")
		}
		if good != "" {
			b.WriteString("Good:\n\n")
			b.WriteString("```good\n" + good + "\n```\n\n")
		}
	}

	if len(d.References) > 0 {
		b.WriteString("## References\n\n")
		for _, ref := range d.References {
			ref = strings.TrimSpace(ref)
			if ref == "" {
				continue
			}
			b.WriteString("- " + ref + "\n")
		}
		b.WriteString("\n")
	}

	return b.String()
}

// renderIndex renders the README index table over defs (already sorted by ID).
func renderIndex(defs []rules.RuleDef) string {
	var b strings.Builder
	b.WriteString("# Rule catalog\n\n")
	b.WriteString(fmt.Sprintf("%d rules. Generated from the rule catalog by `trishul-rulesdoc`; do not edit by hand.\n\n", len(defs)))
	b.WriteString("| ID | Title | Severity | Maturity |\n")
	b.WriteString("| --- | --- | --- | --- |\n")
	for _, d := range defs {
		title := d.Title
		if title == "" {
			title = d.ID
		}
		b.WriteString(fmt.Sprintf("| [%s](%s.md) | %s | %s | %s |\n",
			d.ID, d.ID, escapeCell(title), escapeCell(d.DefaultSeverity), escapeCell(string(d.Maturity))))
	}
	return b.String()
}

func metaRow(field, value string) string {
	if strings.TrimSpace(value) == "" {
		value = "-"
	}
	return "| " + field + " | " + escapeCell(value) + " |\n"
}

func joinOrDash(items []string) string {
	if len(items) == 0 {
		return "-"
	}
	return strings.Join(items, ", ")
}

// escapeCell makes a value safe to place inside a markdown table cell.
func escapeCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
