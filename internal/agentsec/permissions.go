package agentsec

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
)

// Component 5: permission & sandbox config.
//
// AI agents gate dangerous actions (shell, file writes, network) behind
// permission prompts and a sandbox. A config change that blanket-allows tools,
// disables approval, or passes a --dangerously-* / --no-sandbox flag silently
// removes that gate — turning a prompt-injection or a malicious task into
// arbitrary execution. This analyzer reads agent config / CI / hook files
// (read-only) and flags those escalations.
//
//	AGENT-PERM-001  blanket allow-all tool permissions
//	AGENT-PERM-002  approval / confirmation disabled (auto-approve, YOLO)
//	AGENT-PERM-003  dangerous CLI flags (--dangerously-*, --no-sandbox)
//	AGENT-PERM-004  security checks disabled
func init() { register(scanPermissions) }

const (
	permTrustBoundary = "untrusted config change -> agent tool/permission scope"
	permWorkflow      = "an AI agent invokes configured tools"
)

type permRule struct {
	checkID     string
	title       string
	severity    string
	confidence  string
	re          *regexp.Regexp
	enabled     string
	remediation string
	cwe         string
}

// permLineRules are scanned per-line so the reported line is exact. Patterns are
// written to tolerate JSON/YAML/shell spelling of the same escalation.
var permLineRules = []permRule{
	{
		checkID: "AGENT-PERM-003", title: "Dangerous permission/sandbox-bypass flag", severity: "HIGH", confidence: "HIGH",
		re:          regexp.MustCompile(`(?i)--dangerously[a-z\-]*|--no-sandbox|--disable-sandbox|--disable-setuid-sandbox|--unsafe(-[a-z]+)*|--skip-permissions|--allow-all|--trust-all-tools?`),
		enabled:     "the agent runs tools with the safety gate (permission prompt / sandbox) removed",
		remediation: "remove the bypass flag; keep permission prompts and the sandbox enabled",
		cwe:         "CWE-250",
	},
	{
		checkID: "AGENT-PERM-002", title: "Agent approval/confirmation disabled", severity: "HIGH", confidence: "HIGH",
		re:          regexp.MustCompile(`(?i)"?(require[_\-]?approval|require[_\-]?confirmation|needs?[_\-]?approval|ask[_\-]?for[_\-]?approval|confirm[_\-]?before[_\-]?run)"?\s*[:=]\s*(false|"false"|no|off|0)\b`),
		enabled:     "tool calls run without a human approval step",
		remediation: "keep approval/confirmation required for tool execution",
		cwe:         "CWE-250",
	},
	{
		checkID: "AGENT-PERM-002", title: "Agent auto-approve / auto-run enabled", severity: "HIGH", confidence: "HIGH",
		re:          regexp.MustCompile(`(?i)"?(auto[_\-]?approve|auto[_\-]?run|auto[_\-]?accept|auto[_\-]?execute|skip[_\-]?confirmation|skip[_\-]?permissions?|yolo(_?mode)?|bypass[_\-]?permissions?)"?\s*[:=]\s*(true|"true"|yes|on|1)\b`),
		enabled:     "the agent auto-executes tool calls with no confirmation",
		remediation: "disable auto-approve / YOLO; require explicit confirmation",
		cwe:         "CWE-250",
	},
	{
		checkID: "AGENT-PERM-001", title: "Blanket allow-all tool permissions (inline)", severity: "HIGH", confidence: "HIGH",
		re:          regexp.MustCompile(`(?i)"?(allow|allowed[_\-]?tools?|permissions?)"?\s*[:=]\s*("?\*"?|\[\s*"\*"\s*\]|"?all"?|"?allow[_\-]?all"?)`),
		enabled:     "every tool is permitted without per-tool review",
		remediation: "replace the wildcard with an explicit least-privilege allow-list",
		cwe:         "CWE-732",
	},
	{
		checkID: "AGENT-PERM-004", title: "Security check disabled", severity: "MEDIUM", confidence: "MEDIUM",
		re:          regexp.MustCompile(`(?i)"?(verify[_\-]?signatures?|signature[_\-]?verification|security[_\-]?checks?|ssl[_\-]?verify|tls[_\-]?verify|strict[_\-]?ssl|strict[_\-]?mode|checksum[_\-]?verification)"?\s*[:=]\s*(false|"false"|no|off|0)\b`),
		enabled:     "an integrity/security verification step is turned off",
		remediation: "re-enable signature/SSL/security verification",
		cwe:         "CWE-732",
	},
	{
		checkID: "AGENT-PERM-004", title: "Security check disabled (environment)", severity: "MEDIUM", confidence: "MEDIUM",
		re:          regexp.MustCompile(`(?i)\bNODE_TLS_REJECT_UNAUTHORIZED\b\s*[:=]\s*"?0"?|\bPYTHONHTTPSVERIFY\b\s*[:=]\s*"?0"?|\bGIT_SSL_NO_VERIFY\b\s*[:=]\s*"?(1|true)"?`),
		enabled:     "TLS/certificate verification is disabled for the agent's network calls",
		remediation: "remove the verification-disabling environment override",
		cwe:         "CWE-732",
	},
}

func scanPermissions(dir string) ([]AgentFinding, error) {
	var out []AgentFinding
	err := WalkFiles(dir, permMatch, func(path string, content []byte) {
		rel := Rel(dir, path)
		lines := SplitLines(content)
		seen := map[string]bool{} // dedup by checkID:line within a file

		for i, line := range lines {
			for _, rule := range permLineRules {
				if !rule.re.MatchString(line) {
					continue
				}
				dkey := rule.checkID + ":" + itoa(i+1)
				if seen[dkey] {
					continue
				}
				seen[dkey] = true
				out = append(out, permFinding(rule, rel, i+1, line))
			}
		}

		// Structured pass: catch multi-line allow-all arrays and bypass modes
		// that a per-line regex cannot see.
		for _, f := range permStructuredJSON(content) {
			dkey := f.checkID + ":" + itoa(f.line)
			if seen[dkey] {
				continue
			}
			seen[dkey] = true
			rule := permRule{
				checkID: f.checkID, title: f.title, severity: "HIGH", confidence: "HIGH",
				enabled:     f.enabled,
				remediation: f.remediation,
				cwe:         f.cwe,
			}
			out = append(out, permFinding(rule, rel, f.line, f.evidence))
		}
	})
	return out, err
}

func permFinding(rule permRule, file string, line int, evidence string) AgentFinding {
	return AgentFinding{
		CheckID:          rule.checkID,
		Title:            rule.title,
		Severity:         rule.severity,
		Confidence:       rule.confidence,
		EntryPoint:       file,
		TrustBoundary:    permTrustBoundary,
		AffectedWorkflow: permWorkflow,
		EnabledAction:    rule.enabled,
		File:             file,
		Line:             line,
		Evidence:         []string{permTrim(evidence)},
		Limitations:      "passive config read; whether this config is active depends on the agent runtime",
		Remediation:      rule.remediation,
		CWE:              rule.cwe,
	}
}

// permMatch selects agent/CI/hook config files worth scanning.
func permMatch(name, path string) bool {
	ln := strings.ToLower(name)
	lp := filepath.ToSlash(strings.ToLower(path))

	switch ln {
	case "claude.md", "agents.md", ".cursorrules", ".windsurfrules", ".pre-commit-config.yaml":
		return true
	}
	if strings.HasSuffix(ln, ".json") {
		if strings.Contains(lp, "/.claude/") || strings.Contains(lp, "/.cursor/") || strings.Contains(lp, "/.codeium/") {
			return true
		}
		if strings.HasPrefix(ln, "settings") || strings.HasSuffix(ln, ".settings.json") {
			return true
		}
	}
	// CI workflows and agent hook files.
	if strings.Contains(lp, "/.github/workflows/") && (strings.HasSuffix(ln, ".yml") || strings.HasSuffix(ln, ".yaml")) {
		return true
	}
	if strings.Contains(lp, "/hooks/") {
		return true
	}
	return false
}

type permStructFinding struct {
	checkID, title, evidence, enabled, remediation, cwe string
	line                                                int
}

// permStructuredJSON parses JSON configs to find allow-all arrays and
// permission-bypass modes spread across multiple lines.
func permStructuredJSON(content []byte) []permStructFinding {
	var top interface{}
	if json.Unmarshal(content, &top) != nil {
		return nil
	}
	lines := SplitLines(content)
	var out []permStructFinding
	permWalkJSON("", top, lines, &out)
	return out
}

func permWalkJSON(key string, v interface{}, lines []string, out *[]permStructFinding) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			lk := strings.ToLower(k)
			// allow-all tool arrays / wildcard strings
			if lk == "allow" || lk == "allowedtools" || lk == "allowed_tools" || lk == "tools" {
				if permHasWildcard(val) {
					*out = append(*out, permStructFinding{
						checkID: "AGENT-PERM-001", title: "Blanket allow-all tool permissions",
						evidence: `"` + k + `": [ "*" ]`, line: permLineOf(lines, `"`+k+`"`),
						enabled:     "every tool is permitted without per-tool review",
						remediation: "replace the wildcard with an explicit least-privilege allow-list",
						cwe:         "CWE-732",
					})
				}
			}
			// permission-bypass default mode
			if lk == "defaultmode" || lk == "mode" || lk == "permissionmode" {
				if s, ok := val.(string); ok {
					ls := strings.ToLower(s)
					if ls == "bypasspermissions" || ls == "yolo" {
						*out = append(*out, permStructFinding{
							checkID: "AGENT-PERM-002", title: "Agent permission mode bypasses approval",
							evidence: `"` + k + `": "` + s + `"`, line: permLineOf(lines, `"`+s+`"`),
							enabled:     "the agent runs in a mode that skips per-action approval",
							remediation: "use a permission mode that prompts for dangerous actions",
							cwe:         "CWE-250",
						})
					}
				}
			}
			permWalkJSON(k, val, lines, out)
		}
	case []interface{}:
		for _, val := range t {
			permWalkJSON(key, val, lines, out)
		}
	}
}

// permHasWildcard reports a blanket allow: a bare "*" string or an array that
// contains a "*" or a broad "X(*)" entry.
func permHasWildcard(v interface{}) bool {
	switch t := v.(type) {
	case string:
		return permIsWildcard(t)
	case []interface{}:
		for _, e := range t {
			if s, ok := e.(string); ok && permIsWildcard(s) {
				return true
			}
		}
	}
	return false
}

func permIsWildcard(s string) bool {
	s = strings.TrimSpace(s)
	if s == "*" || strings.EqualFold(s, "all") || strings.EqualFold(s, "allow-all") {
		return true
	}
	// broad per-tool wildcard like Bash(*) / Bash(:*)
	if strings.HasSuffix(s, "(*)") || strings.HasSuffix(s, "(:*)") {
		return true
	}
	return false
}

func permLineOf(lines []string, needle string) int {
	for i, l := range lines {
		if strings.Contains(l, needle) {
			return i + 1
		}
	}
	return 1
}

func permTrim(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > 160 {
		return s[:157] + "..."
	}
	return s
}

// itoa avoids importing strconv for a single conversion.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
