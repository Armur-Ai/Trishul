package agentsec

// Component 3 — Command & execution-path analysis.
//
// scanExecPath passively inspects the scripts an AI coding agent is most likely
// to trigger without a human reviewing them first: package.json install-lifecycle
// hooks, shell/Makefile install and build scripts, and GitHub Actions workflows.
// It flags execution paths that fetch and run remote code, exfiltrate secrets or
// credentials, or reach new network destinations during install / build / CI.
//
// Analysis is read-only: every script is treated as DATA. Nothing here executes,
// sources, or interpolates any scanned command — the "evidence" is a trimmed,
// descriptive excerpt of the repository's own text, never a synthesized payload.

import (
	"encoding/json"
	"net"
	"path/filepath"
	"regexp"
	"strings"
)

func init() { register(scanExecPath) }

const execTrustBoundary = "untrusted repo script -> code execution during install/build/CI"

// scanExecPath walks dir once and dispatches each relevant file to a scanner.
func scanExecPath(dir string) ([]AgentFinding, error) {
	var out []AgentFinding
	err := WalkFiles(dir, execMatch, func(path string, content []byte) {
		rel := Rel(dir, path)
		base := filepath.Base(path)
		switch {
		case base == "package.json":
			out = append(out, execScanPackageJSON(rel, content)...)
		case execIsWorkflowPath(path) && (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")):
			out = append(out, execScanWorkflow(rel, content)...)
		case execIsMakefile(base):
			out = append(out, execScanMakefile(rel, content)...)
		case strings.HasSuffix(base, ".sh"):
			out = append(out, execScanShell(rel, content)...)
		}
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func execMatch(name, path string) bool {
	switch {
	case name == "package.json":
		return true
	case strings.HasSuffix(name, ".sh"):
		return true
	case execIsMakefile(name):
		return true
	case execIsWorkflowPath(path) && (strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")):
		return true
	}
	return false
}

func execIsMakefile(name string) bool {
	switch name {
	case "Makefile", "makefile", "GNUmakefile", "BSDmakefile":
		return true
	}
	return strings.HasSuffix(name, ".mk")
}

func execIsWorkflowPath(path string) bool {
	return strings.Contains(filepath.ToSlash(path), "/.github/workflows/")
}

// ---------------------------------------------------------------------------
// package.json lifecycle scripts
// ---------------------------------------------------------------------------

func execScanPackageJSON(rel string, content []byte) []AgentFinding {
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(content, &pkg); err != nil || pkg.Scripts == nil {
		return nil
	}
	lines := SplitLines(content)
	var out []AgentFinding
	for _, key := range []string{"preinstall", "install", "postinstall", "prepare"} {
		cmd, ok := pkg.Scripts[key]
		if !ok || strings.TrimSpace(cmd) == "" {
			continue
		}
		line := execKeyLine(lines, key)
		if hit, ok := execClassify(cmd); ok {
			out = append(out, execFinding("AGENT-EXEC-001",
				execTitle("package.json "+key+" script", hit), hit.sev, hit.conf,
				rel, "an AI agent installs dependencies", hit.enabled, hit.cwe,
				rel, line, hit.evidence, ""))
			continue
		}
		// Not clearly malicious, but an inline shell / eval in an install hook is
		// still an agent-triggered code-execution path. A plain compile command
		// (tsc, node-gyp rebuild, webpack, ...) matches nothing here and stays clean.
		if execInlineShell(cmd) {
			out = append(out, execFinding("AGENT-EXEC-001",
				"package.json "+key+" script runs an inline shell/eval command",
				"MEDIUM", "LOW", rel, "an AI agent installs dependencies",
				"executes an inline shell or eval command automatically when dependencies are installed",
				"CWE-829, CWE-77", rel, line, execTrim(cmd), ""))
		}
	}
	return out
}

func execKeyLine(lines []string, key string) int {
	needle := `"` + key + `"`
	for i, ln := range lines {
		if strings.Contains(ln, needle) {
			return i + 1
		}
	}
	return 1
}

// ---------------------------------------------------------------------------
// shell scripts
// ---------------------------------------------------------------------------

func execScanShell(rel string, content []byte) []AgentFinding {
	var out []AgentFinding
	for _, seg := range execLogical(SplitLines(content)) {
		t := strings.TrimSpace(seg.text)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if hit, ok := execClassify(t); ok {
			out = append(out, execFinding("AGENT-EXEC-002",
				execTitle("Install/build script", hit), hit.sev, hit.conf,
				rel, "an AI agent runs tests or builds", hit.enabled, hit.cwe,
				rel, seg.line, hit.evidence, ""))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Makefile recipes
// ---------------------------------------------------------------------------

var execTargetRe = regexp.MustCompile(`^([A-Za-z0-9_./%-]+)\s*:`)

func execScanMakefile(rel string, content []byte) []AgentFinding {
	lines := SplitLines(content)
	var out []AgentFinding
	target := ""
	for i := 0; i < len(lines); {
		first := lines[i]
		start := i + 1
		cur := strings.TrimRight(first, "\r")
		for strings.HasSuffix(cur, `\`) && i+1 < len(lines) {
			cur = strings.TrimSuffix(cur, `\`) + " " + strings.TrimRight(lines[i+1], "\r")
			i++
		}
		i++

		trimmed := strings.TrimSpace(cur)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(first, "\t") { // not a recipe line
			if m := execTargetRe.FindStringSubmatch(trimmed); m != nil {
				target = m[1]
			}
			continue
		}
		cmd := strings.TrimLeft(trimmed, "@-+ ") // strip recipe-line prefixes
		if hit, ok := execClassify(cmd); ok {
			title := execTitle("Makefile recipe", hit)
			if target != "" {
				title += " (target " + target + ")"
			}
			out = append(out, execFinding("AGENT-EXEC-002",
				title, hit.sev, hit.conf, rel, "an AI agent runs tests or builds",
				hit.enabled, hit.cwe, rel, start, hit.evidence, ""))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// GitHub Actions workflows
// ---------------------------------------------------------------------------

var execRunRe = regexp.MustCompile(`^(\s*)(?:-\s+)?run:\s*(.*)$`)

func execScanWorkflow(rel string, content []byte) []AgentFinding {
	lines := SplitLines(content)
	lc := strings.ToLower(string(content))
	var out []AgentFinding

	// pull_request_target that checks out the untrusted PR head and then runs it:
	// the workflow executes attacker-controlled code with access to repo secrets.
	if strings.Contains(lc, "pull_request_target") && strings.Contains(lc, "actions/checkout") &&
		(strings.Contains(lc, "pull_request.head") || strings.Contains(lc, "head.ref") ||
			strings.Contains(lc, "head.sha") || strings.Contains(lc, "github.head_ref")) {
		out = append(out, execFinding("AGENT-EXEC-003",
			"pull_request_target workflow checks out and runs untrusted PR code",
			"HIGH", "MEDIUM", rel, "an AI agent runs tests or builds",
			"runs code from an attacker-controlled pull request with access to repository secrets",
			"CWE-829", rel, execLineContains(lines, "pull_request_target"),
			"on: pull_request_target with checkout of the PR head followed by run steps", ""))
	}

	for i := 0; i < len(lines); {
		m := execRunRe.FindStringSubmatch(lines[i])
		if m == nil {
			i++
			continue
		}
		indent := len(m[1])
		rest := strings.TrimSpace(m[2])
		start := i + 1
		var block string
		if execIsBlockScalar(rest) {
			var sb []string
			i++
			for i < len(lines) {
				ln := lines[i]
				if strings.TrimSpace(ln) == "" {
					sb = append(sb, "")
					i++
					continue
				}
				if execIndent(ln) <= indent {
					break
				}
				sb = append(sb, strings.TrimSpace(ln))
				i++
			}
			block = strings.Join(sb, "\n")
		} else {
			block = rest
			i++
		}
		out = append(out, execAnalyzeRun(rel, block, start)...)
	}
	return out
}

func execIsBlockScalar(rest string) bool {
	switch rest {
	case "", "|", ">", "|-", ">-", "|+", ">+":
		return true
	}
	return false
}

func execAnalyzeRun(rel, block string, line int) []AgentFinding {
	if strings.TrimSpace(block) == "" {
		return nil
	}
	// A run step that references a repository secret and also talks to a
	// non-allowlisted host is an exfiltration path.
	if strings.Contains(strings.ToLower(block), "secrets.") {
		if ext := execExternalURLs(block); len(ext) > 0 {
			return []AgentFinding{execFinding("AGENT-EXEC-003",
				"CI workflow step exfiltrates a repository secret", "HIGH", "HIGH",
				rel, "an AI agent runs tests or builds",
				"sends a repository secret to "+execHost(ext[0]),
				"CWE-829, CWE-200", rel, line, execTrim(block), "")}
		}
	}
	if hit, ok := execClassify(block); ok {
		return []AgentFinding{execFinding("AGENT-EXEC-003",
			execTitle("CI workflow step", hit), hit.sev, hit.conf,
			rel, "an AI agent runs tests or builds", hit.enabled, hit.cwe,
			rel, line, hit.evidence, "")}
	}
	return nil
}

func execIndent(s string) int {
	n := 0
	for _, r := range s {
		if r == ' ' || r == '\t' {
			n++
			continue
		}
		break
	}
	return n
}

func execLineContains(lines []string, sub string) int {
	sub = strings.ToLower(sub)
	for i, ln := range lines {
		if strings.Contains(strings.ToLower(ln), sub) {
			return i + 1
		}
	}
	return 1
}

// ---------------------------------------------------------------------------
// command classifier (shared across all script kinds)
// ---------------------------------------------------------------------------

type execHit struct {
	sev, conf string
	cwe       string
	enabled   string
	evidence  string
}

// execClassify decides whether a single command is a risky execution path.
// Conservative by design: an ordinary build/test command returns ok=false.
func execClassify(cmd string) (execHit, bool) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return execHit{}, false
	}
	ext := execExternalURLs(cmd)

	// 1. Exfiltration of secrets/credentials (most specific).
	if host, ok := execExfiltrates(cmd); ok {
		return execHit{
			sev: "HIGH", conf: "HIGH", cwe: "CWE-829, CWE-200",
			enabled:  "reads secret/credential material and sends it to " + execOr(host, "an external host"),
			evidence: execTrim(cmd),
		}, true
	}

	// 2. Fetched or decoded content piped into a shell interpreter = remote code exec.
	if execPipeToShell(cmd) {
		fetch := execHasFetch(cmd)
		b64 := strings.Contains(strings.ToLower(cmd), "base64")
		enabled := "executes arbitrary shell commands piped from local data"
		switch {
		case fetch && len(ext) > 0:
			enabled = "downloads code from " + execHost(ext[0]) + " and executes it in a shell"
		case fetch:
			enabled = "downloads remote code and executes it in a shell"
		case b64:
			enabled = "decodes an embedded payload and executes it in a shell"
		}
		return execHit{
			sev: "HIGH", conf: "HIGH", cwe: "CWE-829, CWE-77",
			enabled: enabled, evidence: execTrim(cmd),
		}, true
	}

	// 3. Touching credential material during install/build.
	if execTouchesCreds(cmd) {
		return execHit{
			sev: "HIGH", conf: "MEDIUM", cwe: "CWE-829",
			enabled:  "reads or writes sensitive credential files (SSH/AWS/npm/env)",
			evidence: execTrim(cmd),
		}, true
	}

	// 4. Fetching code/content from a non-allowlisted network destination.
	if execHasFetch(cmd) && len(ext) > 0 {
		return execHit{
			sev: "MEDIUM", conf: "MEDIUM", cwe: "CWE-829",
			enabled:  "downloads content from non-allowlisted host " + execHost(ext[0]),
			evidence: execTrim(cmd),
		}, true
	}

	return execHit{}, false
}

func execTitle(prefix string, hit execHit) string {
	switch {
	case strings.Contains(hit.cwe, "200"):
		return prefix + " exfiltrates secrets to a remote host"
	case strings.Contains(hit.cwe, "77"):
		return prefix + " pipes remote/opaque code into a shell"
	case hit.sev == "MEDIUM":
		return prefix + " fetches code from a non-allowlisted host"
	default:
		return prefix + " accesses credential files"
	}
}

var execShellInterp = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "ash": true,
	"python": true, "python2": true, "python3": true, "ruby": true, "perl": true,
	"node": true, "nodejs": true, "php": true,
}

// execPipeToShell reports whether cmd pipes anything into a shell interpreter.
func execPipeToShell(cmd string) bool {
	parts := strings.Split(cmd, "|")
	for i := 1; i < len(parts); i++ {
		fields := strings.Fields(parts[i])
		if len(fields) == 0 {
			continue
		}
		tok := fields[0]
		if tok == "sudo" && len(fields) > 1 {
			tok = fields[1]
		}
		if execShellInterp[filepath.Base(tok)] {
			return true
		}
	}
	return false
}

func execInlineShell(cmd string) bool {
	lc := strings.ToLower(cmd)
	for _, p := range []string{"sh -c", "bash -c", "zsh -c", "eval ", "node -e", "python -c", "python3 -c", "perl -e", "ruby -e"} {
		if strings.Contains(lc, p) {
			return true
		}
	}
	return false
}

func execHasFetch(cmd string) bool {
	lc := strings.ToLower(cmd)
	for _, p := range []string{"curl", "wget", "invoke-webrequest", "iwr ", "lwp-request", "httpie", "http get"} {
		if strings.Contains(lc, p) {
			return true
		}
	}
	return false
}

var execCredPaths = []string{
	"/.ssh", "~/.ssh", ".ssh/", "id_rsa", "id_ed25519", "id_dsa",
	"/.aws", "~/.aws", ".aws/credentials", "/.gnupg", "~/.gnupg",
	"/.kube", "~/.kube", ".netrc", "/.docker/config", "~/.docker/config",
}

func execTouchesCreds(cmd string) bool {
	lc := strings.ToLower(cmd)
	for _, p := range execCredPaths {
		if strings.Contains(lc, p) {
			return true
		}
	}
	// .npmrc / .env are legitimately present; only flag when written to.
	if (strings.Contains(lc, ".npmrc") || strings.Contains(lc, "/.env") || strings.Contains(lc, " .env")) && execWrites(lc) {
		return true
	}
	return false
}

func execWrites(lc string) bool {
	for _, p := range []string{">", ">>", "tee ", "echo ", "printf ", "cp ", "mv ", "install -"} {
		if strings.Contains(lc, p) {
			return true
		}
	}
	return false
}

var execSecretTokens = []string{
	"${{ secrets.", "${{secrets.", "secrets.", "secret", "token", "password", "passwd",
	"api_key", "apikey", "aws_secret", "aws_access", "private_key", "private key",
	"npm_token", "gh_token", "github_token", "printenv", "process.env", "$env:",
	"id_rsa", "id_ed25519", ".ssh/", "-----begin",
}

// execExfiltrates reports a secret/credential read combined with an off-host sink
// (a non-allowlisted URL or a raw network tool). Returns the destination host.
func execExfiltrates(cmd string) (string, bool) {
	lc := strings.ToLower(cmd)
	secret := false
	for _, p := range execSecretTokens {
		if strings.Contains(lc, p) {
			secret = true
			break
		}
	}
	if !secret {
		return "", false
	}
	if ext := execExternalURLs(cmd); len(ext) > 0 {
		return execHost(ext[0]), true
	}
	for _, p := range []string{"nc ", "ncat ", "/dev/tcp/", "telnet ", "scp ", "| mail"} {
		if strings.Contains(lc, p) {
			return "a remote host", true
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------
// URL / host allowlisting
// ---------------------------------------------------------------------------

var execURLRe = regexp.MustCompile("(?i)https?://[a-z0-9.\\-]+(?::[0-9]+)?[^\\s\"'`)|><]*")

// execExternalURLs returns the de-duplicated URLs in cmd whose host is not on the
// package-infrastructure allowlist (new network destinations).
func execExternalURLs(cmd string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range execURLRe.FindAllString(cmd, -1) {
		if execAllowedHost(execHost(m)) || seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	return out
}

func execHost(u string) string {
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimPrefix(u, "HTTPS://")
	u = strings.TrimPrefix(u, "HTTP://")
	if i := strings.IndexAny(u, "/:?#"); i >= 0 {
		u = u[:i]
	}
	return strings.ToLower(u)
}

var execAllowBase = []string{
	"npmjs.org", "npmjs.com", "yarnpkg.com", "nodejs.org", "github.com", "githubusercontent.com",
	"pypi.org", "pythonhosted.org", "python.org", "crates.io", "golang.org", "go.dev", "googlesource.com",
	"rubygems.org", "debian.org", "ubuntu.com", "alpinelinux.org", "archlinux.org", "nuget.org",
	"apache.org", "sourceforge.net", "gradle.org", "maven.org", "docker.com", "docker.io",
	"gnu.org", "kernel.org", "rust-lang.org",
}

func execAllowedHost(h string) bool {
	if h == "" {
		return true // nothing to flag
	}
	if net.ParseIP(h) != nil {
		return false // a raw IP is never allowlisted
	}
	for _, b := range execAllowBase {
		if h == b || strings.HasSuffix(h, "."+b) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

type execSeg struct {
	text string
	line int
}

// execLogical joins backslash line-continuations into one logical command each.
func execLogical(lines []string) []execSeg {
	var segs []execSeg
	for i := 0; i < len(lines); {
		start := i + 1
		cur := strings.TrimRight(lines[i], "\r")
		for strings.HasSuffix(cur, `\`) && i+1 < len(lines) {
			cur = strings.TrimSuffix(cur, `\`) + " " + strings.TrimRight(lines[i+1], "\r")
			i++
		}
		i++
		segs = append(segs, execSeg{text: cur, line: start})
	}
	return segs
}

func execTrim(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 160 {
		s = s[:157] + "..."
	}
	return s
}

func execOr(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func execFinding(checkID, title, sev, conf, entry, affected, enabled, cwe, file string, line int, evidence, remediation string) AgentFinding {
	if remediation == "" {
		remediation = "Review and pin this script before an AI agent installs dependencies, builds, or runs CI. " +
			"Do not pipe remote content into a shell, do not read or write credential/secret files, " +
			"and vendor and verify any downloaded code against a known checksum."
	}
	return AgentFinding{
		CheckID:          checkID,
		Title:            title,
		Severity:         sev,
		Confidence:       conf,
		EntryPoint:       entry,
		TrustBoundary:    execTrustBoundary,
		AffectedWorkflow: affected,
		EnabledAction:    enabled,
		File:             file,
		Line:             line,
		Evidence:         []string{evidence},
		Limitations: "Static heuristic over script text; the command is reported as data and was not executed. " +
			"Confirm the command's intent and destination before trusting or blocking it.",
		Remediation: remediation,
		CWE:         cwe,
	}
}
