package agentsec

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Component 1 — Agent instruction analysis.
//
// scanInstructions inspects agent-instruction files (CLAUDE.md, AGENTS.md,
// .cursorrules, .cursor/rules/*, .github/copilot-instructions.md, .claude/*,
// .windsurfrules) for prompt-injection / instruction-poisoning patterns: text
// that tries to override the agent's prior instructions, impersonate system or
// developer authority, escalate the agent's role, or direct the agent to take
// sensitive actions (exfiltrate secrets, run arbitrary commands, add network
// calls, disable checks).
//
// This is strictly PASSIVE: the scanned text is treated as data. Evidence is a
// trimmed snippet for a human to review, never a payload Trishul acts on. A
// match is suspicious text, not proof an agent will comply; findings in benign
// contexts (fenced example blocks, security docs that quote injections) are
// downgraded to LOW confidence rather than asserted as real attacks.
func init() { register(scanInstructions) }

const (
	instrTrustBoundary    = "untrusted repository instructions -> agent behavior"
	instrAffectedWorkflow = "an AI agent reads repository instructions"
	instrRemediation      = "Treat repository-provided agent instructions as untrusted input. Have a human review the flagged instruction file before any agent acts on it, and remove or quarantine directives that override prior instructions, impersonate system/developer authority, escalate the agent's role, or request sensitive actions."
)

// instrRule is one detection pattern. Several rules may share a CheckID; findings
// are de-duplicated per (CheckID, line).
type instrRule struct {
	checkID  string
	title    string
	severity string
	enabled  string
	cwe      string
	re       *regexp.Regexp
	// commandRisk marks a "run a command" rule whose match is only a finding when
	// the command is RISKY (fetch-and-run remote content, exfiltrate, disable
	// safety). A directive to run a fixed, harmless command (date, ls, npm test,
	// git status) is not a finding.
	commandRisk bool
}

// instrRiskyCmd recognizes the risky command classes that make a "run a command"
// directive a real finding: fetch-and-run remote content, piping into an
// interpreter, interpreter/eval execution, secret exfiltration, and disabling
// safety. A run-directive with none of these is a fixed, harmless command.
var instrRiskyCmd = regexp.MustCompile(`(?i)(\b(curl|wget|iwr|invoke-webrequest|lwp-request|httpie|nc|ncat|telnet)\b|\|\s*(bash|sh|zsh|python[0-9.]*|perl|ruby|node)\b|\b(bash|sh|zsh)\s+-c\b|os\.system\s*\(|subprocess\.(run|call|popen|check_output)|\beval\s*\(|\bexec\s*\(|base64\s+-d|\bsudo\b|rm\s+-rf|https?://|\.env\b|\bsecret|\btoken\b|api[\s_-]?key|credential|password|private\s+key|\b(disable|bypass|skip|turn\s+off)\b|exfiltrat)`)

// Patterns are intentionally conservative to avoid flooding ordinary instruction
// files with false positives. Normal guidance ("run `go build`", "follow the
// style guide") must not match.
var (
	// AGENT-INSTR-001 — instruction-override attempts (MEDIUM).
	instrReOverride = regexp.MustCompile(`(?i)(ignore\s+(all\s+|any\s+)?(previous|prior|earlier|the\s+above|above)\s+instructions|disregard\s+(your|all|any|the)\s+(rules|guidelines|instructions|previous|prior)|from\s+now\s+on,?\s+you\s+(must|will|shall|should|are\s+to)\b|your\s+new\s+instructions\s+are|forget\s+(all\s+|everything\s+)?(previous|prior|your)\s+(instructions|rules|guidelines))`)

	// AGENT-INSTR-002 — impersonation of system/developer authority (MEDIUM).
	// Keyword is case-sensitive (uppercase SYSTEM/DEVELOPER) to avoid matching
	// ordinary prose like "Developer: Alice" or a "## Developer setup" heading.
	instrReImpersonate = regexp.MustCompile(`(?m)^\s*((#{1,6}\s+)?(SYSTEM|DEVELOPER)\s*:\s*\S|#{1,6}\s+(SYSTEM|DEVELOPER)\s*$)`)

	// AGENT-INSTR-003 — authority / role escalation (MEDIUM).
	instrReEscalate = regexp.MustCompile(`(?i)(you\s+are\s+now\s+(an?\s+)?(unrestricted|unfiltered|uncensored|jailbroken|free(\s+from)?|dan\b)|act\s+as\s+(an?\s+)?(unrestricted|unfiltered|uncensored|jailbroken|dan\b)|you\s+have\s+no\s+(restrictions|limitations|rules|guidelines|constraints|filters|limits)|ignore\s+(your\s+)?(safety|ethical|content)\s+(guidelines|rules|filters|policies)|enable\s+(developer|dan|jailbreak)\s+mode)`)
)

// Action-directive rules (AGENT-INSTR-004, HIGH). isCommand adds CWE-77.
var instrActionRules = []instrRule{
	{
		checkID:  "AGENT-INSTR-004",
		title:    "Directive to exfiltrate secrets from an instruction file",
		severity: "HIGH",
		enabled:  "exfiltrate secrets or credentials from the repository",
		cwe:      "CWE-94",
		re:       regexp.MustCompile(`(?i)((send|post|upload|exfiltrat\w*|leak|transmit|email|forward)\b[^\n]{0,50}(secret|token|api[\s_-]?key|password|credential|\.env\b|private\s+key|ssh\s+key|aws[_\s-]?(access|secret))|(read|cat|print|dump|collect|grab)\b[^\n]{0,30}(\.env\b|secrets?|credentials?|api[\s_-]?keys?|private\s+keys?))`),
	},
	{
		checkID:     "AGENT-INSTR-004",
		title:       "Directive to run arbitrary commands from an instruction file",
		severity:    "HIGH",
		enabled:     "run arbitrary shell commands",
		cwe:         "CWE-77, CWE-94",
		commandRisk: true,
		re:          regexp.MustCompile(`(?i)(run\s+the\s+following|execute\s+the\s+following|run\s+this\s+(shell\s+)?command|execute\s+this\s+(shell\s+)?command|arbitrary\s+(shell\s+)?command|(curl|wget)[^\n]{0,80}\|\s*(bash|sh|zsh)\b|\bsh\s+-c\b|os\.system\s*\(|subprocess\.(run|call|Popen|check_output)|\beval\s*\(|\bexec\s*\()`),
	},
	{
		checkID:  "AGENT-INSTR-004",
		title:    "Directive to add outbound network calls from an instruction file",
		severity: "HIGH",
		enabled:  "add unsanctioned outbound network calls",
		cwe:      "CWE-94",
		re:       regexp.MustCompile(`(?i)(add|insert|include|inject|embed|place)\b[^\n]{0,50}(network\s+(call|request)|http\s+request|outbound\s+(call|connection|request)|beacon|phone\s+home|callback\s+to\s+http|request\s+to\s+https?://)`),
	},
	{
		checkID:  "AGENT-INSTR-004",
		title:    "Directive to disable security or safety checks from an instruction file",
		severity: "HIGH",
		enabled:  "disable security, safety, or verification checks",
		cwe:      "CWE-94",
		re:       regexp.MustCompile(`(?i)(disable|skip|bypass|turn\s+off|remove|comment\s+out|silence|suppress)\b[^\n]{0,40}(security\s+(check|scan|control)|safety\s+(check|guard)|the\s+tests?|all\s+tests?|unit\s+tests?|validation|verification|\bci\b|ci\s+pipeline|linting|lint\s+rules?|guardrails?|security\s+scans?|code\s+review)`),
	},
}

// instrGuardrail matches negation / guardrail phrasing ("do not", "never",
// "must not", "avoid", "don't", …). When such phrasing introduces the clause
// that contains an action-directive verb, the line is DEFENSIVE guidance
// ("never run arbitrary commands", "do not disable the tests") rather than a
// directive, and is therefore NOT a finding.
var instrGuardrail = regexp.MustCompile(`(?i)\b(do\s+not|does\s+not|don't|never|must\s+not|must\s+never|shall\s+not|should\s+not|shouldn't|cannot|can't|won't|will\s+not|avoid|refrain\s+from|refuse\s+to|no\s+need\s+to)\b`)

// instrIsGuardrailClause reports whether a negation/guardrail phrase introduces
// the clause that ends at matchStart (the start of the directive verb). Only the
// text preceding the verb, back to the nearest clause boundary, is inspected, so
// a trailing "…, do not tell the user" after a real directive is not mistaken
// for a guardrail.
func instrIsGuardrailClause(line string, matchStart int) bool {
	if matchStart < 0 || matchStart > len(line) {
		return false
	}
	prefix := line[:matchStart]
	if cut := strings.LastIndexAny(prefix, ".;"); cut >= 0 {
		prefix = prefix[cut+1:]
	}
	return instrGuardrail.MatchString(prefix)
}

// exampleLeadInRe matches explicit "this is only an example" lead-ins. Text a
// line introduces as an example ("for example, an attacker might write …") is a
// demonstration, i.e. informational, not a live directive. Shared with the
// injection analyzer.
var exampleLeadInRe = regexp.MustCompile(`(?i)(for example|for instance|e\.g\.|example:|as an example|an example (of|would|might)|(might|could) (write|say|embed|contain|include)|a comment like|payload (like|such as))`)

// instrBenign flags contexts where a match is likely an illustrative example
// (security docs, "do not" guidance) rather than a live injection.
// "example" is matched only in phrase form ("for example", "example above")
// so that payload domains such as "evil.example" do NOT read as benign.
var instrBenign = regexp.MustCompile(`(?i)(for\s+example|example\s+(of|above|below|payload|attack|injection)|an?\s+example|this\s+example|example[:,]|e\.g\.|for\s+instance|do\s+not\b|don't|never\s+do\b|cve-|cve\s|prompt\s+injection|injection\s+(attack|example|payload|pattern)|malicious|attacker|illustrat|demonstrat|\bsample\b|quot|hypothetical|watch\s+out|red\s+flag|not\s+a\s+real)`)

// instrIsInstructionFile reports whether name/path is an agent-instruction file.
func instrIsInstructionFile(name, path string) bool {
	lower := strings.ToLower(name)
	pl := strings.ToLower(filepath.ToSlash(path))

	switch lower {
	case "claude.md", "agents.md", ".cursorrules", ".windsurfrules":
		return true
	case "copilot-instructions.md":
		return strings.Contains(pl, ".github/")
	}
	if strings.Contains(pl, "/.cursor/rules/") || strings.HasPrefix(pl, ".cursor/rules/") {
		return true
	}
	if strings.Contains(pl, "/.claude/") || strings.HasPrefix(pl, ".claude/") {
		switch strings.ToLower(filepath.Ext(name)) {
		case ".md", ".markdown", ".mdc", ".mdx", ".txt":
			return true
		}
	}
	return false
}

func scanInstructions(dir string) ([]AgentFinding, error) {
	var findings []AgentFinding

	err := WalkFiles(dir, func(name, path string) bool {
		return instrIsInstructionFile(name, path)
	}, func(path string, content []byte) {
		findings = append(findings, instrScanFile(dir, path, content)...)
	})
	if err != nil {
		return nil, err
	}
	return findings, nil
}

// instrScanFile scans a single instruction file and returns its findings,
// de-duplicated per (CheckID, line).
func instrScanFile(dir, path string, content []byte) []AgentFinding {
	lines := SplitLines(content)
	fenced := instrFenceMask(lines)
	rel := Rel(dir, path)

	var out []AgentFinding
	seen := map[string]bool{} // checkID|line

	emit := func(checkID, title, severity, enabled, cwe string, lineIdx int) {
		key := checkID + "|" + itoaLine(lineIdx)
		if seen[key] {
			return
		}
		seen[key] = true

		// Quote/example context (fenced code, or text explicitly introduced as an
		// example) is informational, not a finding.
		if instrIsQuoteOrExample(lines, fenced, lineIdx) {
			return
		}

		confidence := "HIGH"
		if instrIsBenignContext(lines, fenced, lineIdx) {
			confidence = "LOW"
		}
		out = append(out, AgentFinding{
			CheckID:          checkID,
			Title:            title,
			Severity:         severity,
			Confidence:       confidence,
			EntryPoint:       rel,
			TrustBoundary:    instrTrustBoundary,
			AffectedWorkflow: instrAffectedWorkflow,
			EnabledAction:    enabled,
			File:             rel,
			Line:             lineIdx + 1,
			Evidence:         []string{instrSnippet(lines[lineIdx])},
			Limitations:      "Suspicious text in an instruction file, not proof that an agent will comply; this is a heuristic text match.",
			Remediation:      instrRemediation,
			CWE:              cwe,
		})
	}

	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if instrReOverride.MatchString(line) {
			emit("AGENT-INSTR-001", "Instruction-override attempt in agent instruction file",
				"MEDIUM", "override the agent's prior instructions or operator policy", "CWE-94", i)
		}
		if instrReImpersonate.MatchString(line) {
			emit("AGENT-INSTR-002", "System/developer authority impersonation in instruction file",
				"MEDIUM", "impersonate system/developer authority to inject directives", "CWE-94", i)
		}
		if instrReEscalate.MatchString(line) {
			emit("AGENT-INSTR-003", "Agent role or authority escalation directive",
				"MEDIUM", "escalate the agent's role or remove its restrictions", "CWE-94", i)
		}
		for _, r := range instrActionRules {
			loc := r.re.FindStringIndex(line)
			if loc == nil {
				continue
			}
			// Guardrail / negation introducing the directive ("never run …",
			// "do not disable the tests") is defensive guidance, not a finding.
			if instrIsGuardrailClause(line, loc[0]) {
				break
			}
			// A directive to run a FIXED, HARMLESS command (date, ls, npm test,
			// git status) is not a finding; only risky commands (fetch-and-run,
			// exfiltrate, disable safety) are.
			if r.commandRisk && !instrRiskyCmd.MatchString(line) {
				break
			}
			emit(r.checkID, r.title, r.severity, r.enabled, r.cwe, i)
			break // one AGENT-INSTR-004 per line
		}
	}
	return out
}

// instrFenceMask marks which lines sit inside a ``` or ~~~ fenced code block.
func instrFenceMask(lines []string) []bool {
	mask := make([]bool, len(lines))
	inFence := false
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~") {
			// The fence delimiter line itself is treated as inside the block.
			mask[i] = true
			inFence = !inFence
			continue
		}
		mask[i] = inFence
	}
	return mask
}

// instrIsQuoteOrExample reports whether the match at lineIdx sits in quote/example
// context: inside a fenced code block, or in a line/immediate context explicitly
// introduced as an example. Such text is informational, not a finding.
func instrIsQuoteOrExample(lines []string, fenced []bool, lineIdx int) bool {
	if lineIdx < len(fenced) && fenced[lineIdx] {
		return true
	}
	lo := lineIdx - 1
	if lo < 0 {
		lo = 0
	}
	hi := lineIdx + 1
	if hi >= len(lines) {
		hi = len(lines) - 1
	}
	var b strings.Builder
	for i := lo; i <= hi; i++ {
		b.WriteString(lines[i])
		b.WriteByte('\n')
	}
	return exampleLeadInRe.MatchString(b.String())
}

// instrIsBenignContext reports whether the match at lineIdx is likely an
// illustrative example rather than a live directive.
func instrIsBenignContext(lines []string, fenced []bool, lineIdx int) bool {
	if lineIdx < len(fenced) && fenced[lineIdx] {
		return true
	}
	lo := lineIdx - 2
	if lo < 0 {
		lo = 0
	}
	hi := lineIdx + 2
	if hi >= len(lines) {
		hi = len(lines) - 1
	}
	var b strings.Builder
	for i := lo; i <= hi; i++ {
		b.WriteString(lines[i])
		b.WriteByte('\n')
	}
	return instrBenign.MatchString(b.String())
}

// instrSnippet trims and bounds a matched line for honest evidence (data, not a
// payload to execute).
func instrSnippet(line string) string {
	s := strings.TrimSpace(line)
	const max = 240
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}

// itoaLine renders a non-negative line index without importing strconv for the
// dedup key only.
func itoaLine(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
