package agentsec

import (
	"fmt"
	"sort"
	"strings"
)

// sortFindings orders findings deterministically (file, line, check id).
func sortFindings(fs []AgentFinding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		if fs[i].Line != fs[j].Line {
			return fs[i].Line < fs[j].Line
		}
		return fs[i].CheckID < fs[j].CheckID
	})
}

// chainRole classifies a finding as an untrusted "entry" (content directed at
// the agent) or an enabled "action" (execution/tool/permission), for correlation.
func chainRole(checkID string) string {
	switch {
	case strings.HasPrefix(checkID, "AGENT-INSTR"),
		strings.HasPrefix(checkID, "AGENT-INJ"),
		strings.HasPrefix(checkID, "AGENT-OBFS"):
		return "entry"
	case strings.HasPrefix(checkID, "AGENT-EXEC"),
		strings.HasPrefix(checkID, "AGENT-MCP"),
		strings.HasPrefix(checkID, "AGENT-PERM"):
		return "action"
	}
	return ""
}

// correlate (Component 7) links individually-suspicious changes into a single
// attack-chain finding when BOTH an untrusted entry point AND an enabled action
// are present in the same repo/PR. This is the pattern that turns low-confidence
// semantic signals (prompt injection) into a corroborated, higher-confidence
// chain — and is exactly why the semantic layer alone never claims high confidence.
func correlate(_ string, findings []AgentFinding) []AgentFinding {
	var entries, actions []AgentFinding
	for _, f := range findings {
		switch chainRole(f.CheckID) {
		case "entry":
			entries = append(entries, f)
		case "action":
			actions = append(actions, f)
		}
	}
	if len(entries) == 0 || len(actions) == 0 {
		return nil
	}
	entry, action := entries[0], actions[0]
	ev := []string{
		fmt.Sprintf("untrusted entry point: %s (%s) at %s:%d", entry.CheckID, entry.Title, entry.File, entry.Line),
		fmt.Sprintf("enabled action: %s (%s) at %s:%d", action.CheckID, action.Title, action.File, action.Line),
	}
	if len(entries) > 1 || len(actions) > 1 {
		ev = append(ev, fmt.Sprintf("(+%d more untrusted-content signal(s), +%d more execution/permission signal(s))", len(entries)-1, len(actions)-1))
	}
	return []AgentFinding{{
		CheckID:          "AGENT-CHAIN-001",
		Title:            "Cross-file agent attack chain: untrusted content + an enabled execution/permission path",
		Severity:         "CRITICAL",
		Confidence:       "HIGH", // two independent signals corroborate each other
		EntryPoint:       entry.File,
		TrustBoundary:    "untrusted repository content -> agent-consumed instruction -> enabled host action",
		AffectedWorkflow: "an AI agent reviews/checks out the PR, reads instructions, then installs deps or runs tools",
		EnabledAction:    action.EnabledAction,
		File:             entry.File,
		Line:             entry.Line,
		Evidence:         ev,
		Limitations:      "Correlation of separate signals; confirm the entry point actually reaches the action in your agent's workflow. Not proof the agent will comply.",
		Remediation:      "Treat neither the untrusted content nor the execution/permission change as trusted from a PR: strip the injected instruction and pin/deny the action.",
		CWE:              "CWE-94",
	}}
}
