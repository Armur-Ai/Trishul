package agenthook

import (
	"os"
	"strings"

	"github.com/rs/zerolog"

	"github.com/Armur-Ai/Trishul/internal/agentsec"
	"github.com/Armur-Ai/Trishul/internal/prgate"
)

// init silences the shared zerolog logger: the built-in scanners log progress
// to stderr, but the hook's stderr is a strict contract read by the agent.
func init() { zerolog.SetGlobalLevel(zerolog.Disabled) }

// defaultScan is the production ScanFunc. It runs Trishul's built-in analyzers
// over dir via internal/prgate (which never executes repository content) and
// maps the results into the hook's Finding shape.
func defaultScan(dir string) ([]Finding, error) {
	scan, err := prgate.ScanDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]Finding, 0, len(scan.Findings))
	for _, f := range scan.Findings {
		out = append(out, Finding{
			RuleID:      f.RuleID,
			Severity:    strings.ToLower(f.Severity),
			Path:        f.Path,
			Line:        f.Line,
			Message:     f.Message,
			Fix:         fixHint(f.RuleID),
			Fingerprint: f.Fingerprint,
		})
	}
	return out, nil
}

// defaultBashScan is the production BashFunc. It reuses the internal/agentsec
// AGENT-EXEC rules by writing the command into a throwaway shell script and
// analyzing it read-only (nothing is executed). Only AGENT-EXEC findings are
// kept; the rm -rf guard is added separately by the engine.
func defaultBashScan(command, _ string) []Finding {
	dir, err := os.MkdirTemp("", "trishul-bash-")
	if err != nil {
		return nil
	}
	defer os.RemoveAll(dir)
	if err := os.WriteFile(dir+"/command.sh", []byte(command+"\n"), 0o600); err != nil {
		return nil
	}
	af, err := agentsec.AnalyzePath(dir)
	if err != nil {
		return nil
	}
	var out []Finding
	for _, f := range af {
		if !strings.HasPrefix(f.CheckID, "AGENT-EXEC") {
			continue
		}
		msg := f.Title
		if f.EnabledAction != "" {
			msg = f.Title + ": " + f.EnabledAction
		}
		out = append(out, Finding{
			RuleID:   f.CheckID,
			Severity: strings.ToLower(f.Severity),
			Line:     0,
			Message:  msg,
			Fix:      f.Remediation,
		})
	}
	return out
}

// fixHint returns a short, rule-aware remediation line for findings whose
// analyzer does not propagate one through SARIF.
func fixHint(ruleID string) string {
	switch {
	case strings.HasPrefix(ruleID, "AGENT-EXEC"):
		return "Remove or pin this install/build/CI step; never fetch-and-run remote code or read/write credential files."
	case strings.HasPrefix(ruleID, "AGENT-"):
		return "Review this agent-surface change for injected instructions or unexpected permission/MCP/tool grants."
	case ruleID == "CWE-798":
		return "Remove the hard-coded secret; load it from an environment variable or a secret manager instead."
	case strings.HasPrefix(ruleID, "CWE-"):
		return "Address the referenced weakness (" + ruleID + ") before the agent relies on this code."
	default:
		return "Review and remediate this finding, or add a reviewed inline suppression with a reason."
	}
}
