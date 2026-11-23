package agentsec

import (
	"path/filepath"
	"strings"
)

// Component 2 — Prompt-injection detection (heuristic/semantic layer).
//
// This analyzer looks for prompt-injection directives embedded in repository
// content that an AI agent may ingest as DATA but that an attacker has crafted
// to be read as INSTRUCTIONS: source-code comments, README/docs Markdown, test
// fixtures, issue/PR templates, and text that looks like laundered tool output.
//
// Dedicated agent-instruction files (CLAUDE.md, AGENTS.md, .cursorrules, ...)
// are intentionally out of scope — those are Component 1's responsibility.
//
// This is a purely semantic/heuristic signal. By itself it can never justify a
// HIGH-confidence claim: Confidence is capped at MEDIUM and every finding's
// Limitations ask for corroboration (a real script, permission, or dependency
// change). The cross-file correlation step raises confidence separately.
func init() { register(scanInjection) }

const (
	injCheckComment  = "AGENT-INJ-001" // directive in a source-code comment
	injCheckDoc      = "AGENT-INJ-002" // directive in documentation / README / fixtures
	injCheckTemplate = "AGENT-INJ-003" // directive in an issue / PR template

	injTrustBoundary = "untrusted repo text -> agent instruction channel"
	injCWE           = "CWE-94"

	injWorkflowRead   = "an AI agent reads repository content"
	injWorkflowReview = "an AI agent reviews the PR"

	injSeverity = "MEDIUM"
	injConfMed  = "MEDIUM"
	injConfLow  = "LOW"

	injLimitations = "Semantic/heuristic match on repository text; a live imperative " +
		"directed at an agent cannot be distinguished from descriptive prose with full " +
		"certainty. Needs corroboration from a real script, permission, or dependency " +
		"change (cross-file correlation) before it can be treated as high confidence."
	injRemediation = "Treat repository text as untrusted data, never as agent " +
		"instructions. Strip or neutralize embedded directives and require human review " +
		"before an agent acts on repository-sourced content."
)

// injCategory classifies a scannable file.
type injCategory int

const (
	injCatNone injCategory = iota
	injCatSource
	injCatDoc
	injCatTemplate
)

// scanInjection walks dir (read-only) and reports prompt-injection directives
// embedded in content an agent may ingest as data.
func scanInjection(dir string) ([]AgentFinding, error) {
	var findings []AgentFinding

	err := WalkFiles(dir, func(name, path string) bool {
		return injClassify(name, path) != injCatNone
	}, func(path string, content []byte) {
		cat := injClassify(filepath.Base(path), path)
		rel := Rel(dir, path)
		lines := SplitLines(content)

		// A file dense with descriptive injection vocabulary (or whose name marks
		// it as security research) is treated as descriptive context: findings in
		// it are capped at LOW so a doc that merely quotes an attack is not flagged
		// as a live directive.
		research := injResearchFile(filepath.Base(path)) || injDescriptiveDensity(content) >= 2

		switch cat {
		case injCatSource:
			findings = append(findings, injScanSource(rel, path, lines, research)...)
		default:
			findings = append(findings, injScanText(rel, path, lines, cat, research)...)
		}
	})
	if err != nil {
		return nil, err
	}
	return findings, nil
}

// injScanSource inspects only the comment text of a source file.
func injScanSource(rel, path string, lines []string, research bool) []AgentFinding {
	var out []AgentFinding
	style := injSourceStyle(path)
	inBlock := false
	for i, raw := range lines {
		text, block := injCommentText(raw, style, inBlock)
		inBlock = block
		if strings.TrimSpace(text) == "" {
			continue
		}
		if f, ok := injEvaluate(text, raw, rel, i+1, injCheckComment, injWorkflowRead, research, false); ok {
			out = append(out, f)
		}
	}
	return out
}

// injScanText inspects every line of a doc / fixture / template file. Lines
// inside Markdown fenced code blocks are treated as descriptive (a demonstration
// rather than a live directive) and capped at LOW.
func injScanText(rel, path string, lines []string, cat injCategory, research bool) []AgentFinding {
	var out []AgentFinding
	check := injCheckDoc
	workflow := injWorkflowRead
	if cat == injCatTemplate {
		check = injCheckTemplate
		workflow = injWorkflowReview
	}
	inFence := false
	for i, raw := range lines {
		if injFenceToggle(raw) {
			inFence = !inFence
			continue
		}
		if f, ok := injEvaluate(raw, raw, rel, i+1, check, workflow, research, inFence); ok {
			out = append(out, f)
		}
	}
	return out
}

// injEvaluate decides whether a single piece of text is an injection directive
// and, if so, builds the finding. descriptive (research file or fenced code) and
// a per-line descriptive marker both downgrade confidence to LOW.
func injEvaluate(text, raw, rel string, line int, check, workflow string, descriptiveCtx, fenced bool) (AgentFinding, bool) {
	lower := strings.ToLower(text)
	sig := injSignals(lower)
	if !sig.candidate() {
		return AgentFinding{}, false
	}

	lineDescriptive := descriptiveCtx || fenced || injHasAny(lower, injDescriptiveMarkers)
	conf := injConfMed
	if lineDescriptive {
		conf = injConfLow
	}

	return AgentFinding{
		CheckID:          check,
		Title:            injTitle(check),
		Severity:         injSeverity,
		Confidence:       conf,
		EntryPoint:       rel,
		TrustBoundary:    injTrustBoundary,
		AffectedWorkflow: workflow,
		EnabledAction:    injActionFor(lower),
		File:             rel,
		Line:             line,
		Evidence:         []string{injTrim(raw)},
		Limitations:      injLimitations,
		Remediation:      injRemediation,
		CWE:              injCWE,
	}, true
}

func injTitle(check string) string {
	switch check {
	case injCheckComment:
		return "Prompt-injection directive embedded in source-code comment"
	case injCheckTemplate:
		return "Prompt-injection directive embedded in issue/PR template"
	default:
		return "Prompt-injection directive embedded in documentation or fixture"
	}
}

// injSig holds the signal flags for one line of candidate text.
type injSig struct {
	override   bool // "ignore previous instructions" and kin
	aiTarget   bool // addresses an AI assistant/agent directly
	imperative bool // a concrete attacker action
	secrecy    bool // instructs the agent to conceal
}

// targetsReader reports whether the text is aimed at the READER agent: an
// instruction-override phrase ("ignore previous instructions"), a direct address
// to an AI assistant/agent or a known coding-agent tool name, or second-person
// imperative framing ("you must …"). Repository text that does not target the
// reading agent is descriptive prose, not an injection.
func (s injSig) targetsReader() bool { return s.override || s.aiTarget }

// candidate is the gate: a bare imperative or a stray AI mention is not enough.
// A finding requires the text to BOTH target the reader agent AND carry a
// concrete malicious action (an imperative) or an instruction to conceal.
func (s injSig) candidate() bool {
	return s.targetsReader() && (s.imperative || s.secrecy)
}

func injSignals(lower string) injSig {
	return injSig{
		override:   injHasAny(lower, injOverridePhrases),
		aiTarget:   injHasAny(lower, injAITargets),
		imperative: injHasAny(lower, injImperatives),
		secrecy:    injHasAny(lower, injSecrecy),
	}
}

// injActionFor returns a human EnabledAction for the strongest imperative in the
// line, so the finding names what the directive tries to make the agent do.
func injActionFor(lower string) string {
	switch {
	case injHasAny(lower, []string{"curl ", "wget ", "| sh", "|sh", "| bash", "|bash", "run the following", "execute the following", "run this command", "run the script", "execute this"}):
		return "execute attacker-controlled commands"
	case injHasAny(lower, []string{"exfiltrate", "leak the", "leak your", "send the", "upload the", "print the secret", "print the env", "read the .env", ".env", "api key", "secret key", "credentials", "access token"}):
		return "exfiltrate secrets or data"
	case injHasAny(lower, []string{"add the dependency", "add this dependency", "add a dependency", "install the package", "npm install", "pip install", "add to package.json", "add a package"}):
		return "introduce an unreviewed dependency"
	case injHasAny(lower, []string{"disable the security", "disable security", "disable the check", "turn off the security", "bypass the", "skip the security", "ignore the security check"}):
		return "disable a security control"
	case injHasAny(lower, []string{"backdoor"}):
		return "insert a backdoor"
	case injHasAny(lower, []string{"do not tell", "don't tell", "without telling", "do not mention", "don't mention", "without informing", "keep this secret", "do not inform"}):
		return "conceal actions from the user"
	default:
		return "follow attacker-controlled instructions"
	}
}

// ---- signal vocabularies (all lowercase) --------------------------------

var injOverridePhrases = []string{
	"ignore previous instructions", "ignore all previous instructions",
	"ignore all prior instructions", "ignore prior instructions",
	"ignore the above instructions", "ignore the previous instructions",
	"ignore your previous instructions", "ignore your instructions",
	"disregard previous instructions", "disregard all previous instructions",
	"disregard the above", "disregard your instructions",
	"forget previous instructions", "forget all previous instructions",
	"forget the above", "override your instructions", "override the system prompt",
	"new instructions:", "updated instructions:", "system prompt:",
}

var injAITargets = []string{
	"ai assistant", "ai agent", "ai model", "ai reviewer", "ai coding assistant",
	"coding assistant", "code assistant", "language model", "large language model",
	"assistant reading this", "agent reading this", "note to the assistant",
	"note to the ai", "attention ai", "attention assistant", "dear ai",
	"to the ai agent", "to the assistant", "hey assistant", "hey copilot",
	"claude code", "copilot:", "cursor agent", "llm agent",
	// Second-person framing addressed to the reading agent.
	"you must", "you should", "you shall", "you are to", "you are now",
	"you will now", "you need to", "you have to", "your task is",
	"your new instructions",
	// Known coding-agent tool names used to address the reader directly.
	"copilot", "github copilot", "chatgpt", "openai assistant", "gemini",
	"windsurf", "aider", "cline agent", "codeium",
}

var injImperatives = []string{
	"run the following", "execute the following", "run this command", "execute this",
	"run the script", "curl ", "wget ", "| sh", "|sh", "| bash", "|bash",
	"exfiltrate", "leak the", "leak your", "send the", "upload the",
	"add the dependency", "add this dependency", "add a dependency",
	"install the package", "npm install", "pip install", "add to package.json",
	"disable the security", "disable security", "disable the check",
	"turn off the security", "bypass the", "skip the security",
	"ignore the security check", "add a backdoor", "insert a backdoor", "backdoor",
	"print the secret", "print the env", "read the .env", "api key", "secret key",
	"credentials", "access token", "override the",
}

var injSecrecy = []string{
	"do not tell the user", "don't tell the user", "without telling the user",
	"without telling", "do not mention", "don't mention", "without informing",
	"keep this secret", "do not inform", "silently",
}

// injDescriptiveMarkers signal that a line is prose ABOUT injection rather than a
// live directive. Their presence caps a finding at LOW.
var injDescriptiveMarkers = []string{
	"for example", "e.g.", "for instance", "such as", "attacker", "adversary",
	"cve-", "cwe-", "owasp", "demonstrat", "proof of concept", "payload",
	"injection attack", "this is an example", "example of", "malicious example",
	"a comment like", "might say", "could say", "may embed", "may contain",
	"hypothetical", "illustrat", "for demonstration", "threat model",
	"an attacker could", "an attacker may", "we detect", "flagged as",
}

func injHasAny(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

func injDescriptiveDensity(content []byte) int {
	lower := strings.ToLower(string(content))
	n := 0
	for _, m := range injDescriptiveMarkers {
		if strings.Contains(lower, m) {
			n++
		}
	}
	return n
}

func injResearchFile(name string) bool {
	lower := strings.ToLower(name)
	for _, m := range []string{
		"security", "injection", "threat", "vuln", "advisory", "attack",
		"exploit", "writeup", "write-up", "whitepaper", "research", "owasp",
		"cwe", "cve", "malware", "redteam", "red-team", "pentest",
	} {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// ---- file classification ------------------------------------------------

func injClassify(name, path string) injCategory {
	if injIsInstructionFile(name, path) {
		return injCatNone
	}
	ext := strings.ToLower(filepath.Ext(name))
	lowerPath := strings.ToLower(filepath.ToSlash(path))

	// Issue / PR templates live under .github and are Markdown.
	if injIsTemplate(name, lowerPath, ext) {
		return injCatTemplate
	}
	if _, ok := injDocExts[ext]; ok {
		return injCatDoc
	}
	if injSourceStyleFor(ext) != "" {
		return injCatSource
	}
	return injCatNone
}

func injIsTemplate(name, lowerPath, ext string) bool {
	if ext != ".md" && ext != ".markdown" {
		return false
	}
	lowerName := strings.ToLower(name)
	if strings.Contains(lowerName, "pull_request_template") {
		return true
	}
	if strings.Contains(lowerPath, "/issue_template/") || strings.Contains(lowerPath, "/.github/issue_template") {
		return true
	}
	return false
}

// injIsInstructionFile marks dedicated agent-instruction files that belong to
// Component 1 and must be skipped here.
func injIsInstructionFile(name, path string) bool {
	lower := strings.ToLower(name)
	switch lower {
	case "claude.md", "agents.md", "agent.md", "gemini.md", "qwen.md",
		".cursorrules", ".windsurfrules", ".clinerules", ".aiderrules",
		"copilot-instructions.md", ".aider.conf.yml", "mcp.json", ".mcp.json":
		return true
	}
	if strings.Contains(lower, "copilot-instructions") {
		return true
	}
	if ext := strings.ToLower(filepath.Ext(name)); ext == ".mdc" { // cursor rule files
		return true
	}
	lowerPath := strings.ToLower(filepath.ToSlash(path))
	if strings.Contains(lowerPath, "/.cursor/rules/") || strings.Contains(lowerPath, "/.github/instructions/") {
		return true
	}
	return false
}

var injDocExts = map[string]bool{
	".md": true, ".markdown": true, ".rst": true, ".txt": true,
	".adoc": true, ".log": true, ".out": true,
}

// injSourceStyleFor maps a source extension to its comment style, or "".
func injSourceStyleFor(ext string) string {
	switch ext {
	case ".go", ".js", ".ts", ".jsx", ".tsx", ".java", ".c", ".h", ".cc", ".cpp",
		".hpp", ".cxx", ".cs", ".rs", ".swift", ".kt", ".kts", ".scala", ".php",
		".proto", ".dart", ".groovy":
		return "slash"
	case ".py", ".rb", ".sh", ".bash", ".zsh", ".pl", ".pm", ".r", ".yaml", ".yml",
		".toml", ".tf", ".ex", ".exs", ".nim":
		return "hash"
	case ".sql", ".lua", ".hs", ".elm", ".ada":
		return "dash"
	}
	return ""
}

func injSourceStyle(path string) string {
	return injSourceStyleFor(strings.ToLower(filepath.Ext(path)))
}

// injCommentText returns the comment portion of a source line (plus the new
// block-comment state). For non-comment code it returns "".
func injCommentText(line, style string, inBlock bool) (string, bool) {
	switch style {
	case "slash":
		if inBlock {
			if end := strings.Index(line, "*/"); end >= 0 {
				return line[:end], false
			}
			return line, true
		}
		if idx := injSlashLineIdx(line); idx >= 0 {
			return line[idx+2:], false
		}
		if b := strings.Index(line, "/*"); b >= 0 {
			rest := line[b+2:]
			if e := strings.Index(rest, "*/"); e >= 0 {
				return rest[:e], false
			}
			return rest, true
		}
		return "", false
	case "hash":
		if idx := strings.Index(line, "#"); idx >= 0 {
			return line[idx+1:], false
		}
		return "", false
	case "dash":
		if idx := strings.Index(line, "--"); idx >= 0 {
			return line[idx+2:], false
		}
		return "", false
	}
	return "", false
}

// injSlashLineIdx finds a "//" line comment while ignoring the "//" inside a
// scheme like "http://" to avoid treating URLs as comments.
func injSlashLineIdx(line string) int {
	from := 0
	for {
		idx := strings.Index(line[from:], "//")
		if idx < 0 {
			return -1
		}
		abs := from + idx
		if abs > 0 && line[abs-1] == ':' {
			from = abs + 2
			continue
		}
		return abs
	}
}

// injFenceToggle reports whether a Markdown line opens/closes a code fence.
func injFenceToggle(line string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~")
}

// injTrim trims a line and caps its length for compact evidence.
func injTrim(line string) string {
	t := strings.TrimSpace(line)
	const max = 200
	if len(t) > max {
		return t[:max] + "..."
	}
	return t
}
