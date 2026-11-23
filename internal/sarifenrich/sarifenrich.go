// Package sarifenrich fills a SARIF log's rules[] metadata from the rule catalog
// and bench precision (P1.2), so GitHub Code Scanning shows rich help, correct
// security-severity, measured precision and CWE tags with a link to each rule's
// doc page.
package sarifenrich

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Armur-Ai/Trishul/internal/rules"
	"github.com/Armur-Ai/Trishul/pkg/sarif"
)

// HelpBaseURL is where per-rule docs are published; helpUri becomes
// HelpBaseURL + "/" + ruleID.
const HelpBaseURL = "https://armur.ai/trishul/rules"

// securitySeverity maps a severity to the GitHub Code Scanning 0–10 numeric
// scale used for sorting/alerting.
func securitySeverity(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return "9.5"
	case "HIGH":
		return "8.0"
	case "MEDIUM":
		return "5.5"
	case "LOW":
		return "3.0"
	default:
		return "1.0"
	}
}

// Enrich sets rules[] metadata for every rule id that appears in the log's
// results, creating a Rule entry when missing. catalog supplies the human
// metadata; precisionByRule (may be nil) supplies the measured precision.
func Enrich(log *sarif.Log, catalog *rules.Catalog, precisionByRule map[string]float64) {
	if log == nil {
		return
	}
	for ri := range log.Runs {
		run := &log.Runs[ri]
		ids := ruleIDsInResults(run)
		existing := map[string]int{}
		for i, r := range run.Tool.Driver.Rules {
			existing[r.ID] = i
		}
		for _, id := range ids {
			idx, ok := existing[id]
			if !ok {
				run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarif.Rule{ID: id})
				idx = len(run.Tool.Driver.Rules) - 1
				existing[id] = idx
			}
			enrichRule(&run.Tool.Driver.Rules[idx], catalog, precisionByRule)
		}
	}
}

func enrichRule(r *sarif.Rule, catalog *rules.Catalog, precisionByRule map[string]float64) {
	if r.Properties == nil {
		r.Properties = map[string]interface{}{}
	}
	r.HelpURI = HelpBaseURL + "/" + r.ID

	var def rules.RuleDef
	var haveDef bool
	if catalog != nil {
		def, haveDef = catalog.Get(r.ID)
	}

	tags := []string{"security"}
	if haveDef {
		if r.Name == "" {
			r.Name = def.Title
		}
		if r.ShortDescription == nil && def.Short != "" {
			r.ShortDescription = &sarif.MultiformatMessageString{Text: def.Short}
		}
		if r.FullDescription == nil && def.Description != "" {
			r.FullDescription = &sarif.MultiformatMessageString{Text: def.Description}
		}
		r.Help = &sarif.MultiformatMessageString{
			Text:     helpText(def),
			Markdown: helpMarkdown(def),
		}
		r.Properties["security-severity"] = securitySeverity(def.DefaultSeverity)
		for _, cwe := range def.CWE {
			if n := cweNumber(cwe); n != "" {
				tags = append(tags, "external/cwe/cwe-"+n)
			}
		}
	}
	if precisionByRule != nil {
		if p, ok := precisionByRule[r.ID]; ok {
			r.Properties["precision"] = p
		}
	}
	r.Properties["tags"] = tags
}

func helpText(def rules.RuleDef) string {
	parts := []string{def.Description}
	if def.Fix != "" {
		parts = append(parts, "Fix: "+def.Fix)
	}
	return strings.Join(parts, "\n\n")
}

func helpMarkdown(def rules.RuleDef) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## %s\n\n%s\n", def.Title, def.Description)
	if def.Fix != "" {
		fmt.Fprintf(&b, "\n### Fix\n\n%s\n", def.Fix)
	}
	if def.Examples.Bad != "" || def.Examples.Good != "" {
		b.WriteString("\n### Examples\n")
		if def.Examples.Bad != "" {
			fmt.Fprintf(&b, "\nBad:\n```\n%s\n```\n", def.Examples.Bad)
		}
		if def.Examples.Good != "" {
			fmt.Fprintf(&b, "\nGood:\n```\n%s\n```\n", def.Examples.Good)
		}
	}
	return b.String()
}

// cweNumber extracts the digits from "CWE-79" -> "79".
func cweNumber(cwe string) string {
	s := strings.ToUpper(strings.TrimSpace(cwe))
	s = strings.TrimPrefix(s, "CWE-")
	for _, r := range s {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return s
}

func ruleIDsInResults(run *sarif.Run) []string {
	seen := map[string]bool{}
	var ids []string
	for _, res := range run.Results {
		if res.RuleID != "" && !seen[res.RuleID] {
			seen[res.RuleID] = true
			ids = append(ids, res.RuleID)
		}
	}
	sort.Strings(ids)
	return ids
}
