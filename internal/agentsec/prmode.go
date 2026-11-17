package agentsec

import "path/filepath"

// FilterToChangedFiles narrows findings to those whose file is in the changed
// set (for PR mode), while ALWAYS keeping cross-file attack-chain findings
// (AGENT-CHAIN-001) — a chain can be newly introduced even if one of its links
// sits on an unchanged line. Paths are compared in cleaned form.
func FilterToChangedFiles(findings []AgentFinding, changed []string) []AgentFinding {
	if len(changed) == 0 {
		return findings
	}
	set := make(map[string]bool, len(changed))
	for _, c := range changed {
		set[filepath.Clean(c)] = true
	}
	out := make([]AgentFinding, 0, len(findings))
	for _, f := range findings {
		if f.CheckID == "AGENT-CHAIN-001" || set[filepath.Clean(f.File)] {
			out = append(out, f)
		}
	}
	return out
}
