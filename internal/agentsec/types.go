// Package agentsec implements Trishul's AI Agent Supply-Chain Security capability:
// detecting malicious instructions and execution paths introduced through
// untrusted pull requests, repositories, dependencies, and development tooling
// that target AI coding agents (Claude Code, Cursor, Codex, Copilot, ...).
//
// Analysis is PASSIVE: analyzers read files only, never execute untrusted
// instructions/hooks/install-scripts/MCP servers, and treat all scanned text as
// data — never as instructions to Trishul's own analysis.
package agentsec

// AgentFinding is one agent-security finding. It is intentionally richer than a
// generic finding so it can name the trust boundary being crossed and keep the
// evidence honest (confidence + limitations).
type AgentFinding struct {
	CheckID          string   `json:"check_id"`
	Title            string   `json:"title"`
	Severity         string   `json:"severity"`   // CRITICAL/HIGH/MEDIUM/LOW/INFO
	Confidence       string   `json:"confidence"` // HIGH/MEDIUM/LOW
	EntryPoint       string   `json:"entry_point,omitempty"`       // the untrusted source
	TrustBoundary    string   `json:"trust_boundary,omitempty"`    // boundary crossed
	AffectedWorkflow string   `json:"affected_workflow,omitempty"` // agent workflow at risk
	EnabledAction    string   `json:"enabled_action,omitempty"`    // requested/enabled action
	File             string   `json:"file"`
	Line             int      `json:"line"`
	Evidence         []string `json:"evidence,omitempty"`
	Limitations      string   `json:"limitations,omitempty"`
	Remediation      string   `json:"remediation,omitempty"`
	CWE              string   `json:"cwe,omitempty"`
}
