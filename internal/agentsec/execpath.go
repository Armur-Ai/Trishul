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
			out = append(out, execScanShell(rel, path, content)...)
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

func execScanShell(rel, path string, content []byte) []AgentFinding {
	var out []AgentFinding
	lines := SplitLines(content)
	gate := newLexGate(path, content)
	for _, seg := range execLogical(lines) {
		t := strings.TrimSpace(seg.text)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		// Only fire for a command that is real executable code — not a comment,
		// a heredoc (cat <<EOF …) usage block, or echo/printf argument text.
		if !gate.shellExecContext(lines[seg.line-1], seg.line-1) {
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
	// YAML comments are not executed, so classify against a comment-stripped copy.
	clean := strings.ToLower(execStripYAMLComments(content))
	var out []AgentFinding

	// pull_request_target that checks out the untrusted PR head and then runs it:
	// the workflow executes attacker-controlled code with access to repo secrets.
	// Only a checkout of the PR head (not the trusted base) that then runs code
	// WITHOUT an environment-approval gate is dangerous.
	if strings.Contains(clean, "pull_request_target") && strings.Contains(clean, "actions/checkout") &&
		(strings.Contains(clean, "pull_request.head") || strings.Contains(clean, "head.ref") ||
			strings.Contains(clean, "head.sha") || strings.Contains(clean, "head_ref")) &&
		strings.Contains(clean, "run:") && // executes the checked-out PR code
		!strings.Contains(clean, "environment:") { // no environment-approval gate
		out = append(out, execFinding("AGENT-EXEC-003",
			"pull_request_target workflow checks out and runs untrusted PR code",
			"HIGH", "MEDIUM", rel, "an AI agent runs tests or builds",
			"runs code from an attacker-controlled pull request with access to repository secrets",
			"CWE-829", rel, execLineContains(lines, "pull_request_target"),
			"on: pull_request_target with checkout of the PR head followed by run steps, and no environment-approval gate", ""))
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

// execStripYAMLComments returns content with every line's trailing comment
// removed, so a commented-out directive is never matched as live configuration.
func execStripYAMLComments(content []byte) string {
	var b strings.Builder
	for _, ln := range SplitLines(content) {
		b.WriteString(execStripComment(ln))
		b.WriteByte('\n')
	}
	return b.String()
}

// execStripComments drops/trims comment text from each line of a run block (shell
// comments inside the script are not executed either).
func execStripComments(block string) string {
	var keep []string
	for _, ln := range strings.Split(block, "\n") {
		if s := execStripComment(ln); strings.TrimSpace(s) != "" {
			keep = append(keep, s)
		}
	}
	return strings.Join(keep, "\n")
}

// execStripComment removes a trailing comment introduced by an unquoted '#' that
// begins the line or is preceded by whitespace. A '#' inside quotes or glued to a
// non-space character (e.g. a URL fragment) is kept.
func execStripComment(line string) string {
	inS, inD := false, false
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case c == '\'' && !inD:
			inS = !inS
		case c == '"' && !inS:
			inD = !inD
		case c == '#' && !inS && !inD && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t'):
			return line[:i]
		}
	}
	return line
}

func execIsBlockScalar(rest string) bool {
	switch rest {
	case "", "|", ">", "|-", ">-", "|+", ">+":
		return true
	}
	return false
}

func execAnalyzeRun(rel, block string, line int) []AgentFinding {
	block = execStripComments(block)
	if strings.TrimSpace(block) == "" {
		return nil
	}
	// A run step that references a repository secret and also talks to a
	// non-allowlisted host is an exfiltration path.
	if strings.Contains(strings.ToLower(block), "secrets.") {
		for _, u := range execExternalURLs(block) {
			h := execHost(u)
			if execSecretToOwnService(block, h) {
				continue // the secret's own service — legitimate, not exfil
			}
			return []AgentFinding{execFinding("AGENT-EXEC-003",
				"CI workflow step exfiltrates a repository secret", "HIGH", "HIGH",
				rel, "an AI agent runs tests or builds",
				"sends a repository secret to "+h,
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
	title     string // optional title suffix; overrides execTitle's heuristic
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

	// 1b. Well-known one-line installers (rustup, nvm, Homebrew, bun, deno, uv,
	// docker) are standard developer practice. Downgrade their fetch-and-run to
	// LOW; if the command additionally pins a checksum, it is not a finding.
	if execIsInstaller(cmd) && (execPipeToShell(cmd) || execHasFetch(cmd)) {
		if execHasChecksum(cmd) {
			return execHit{}, false
		}
		host := execHost(execURLRe.FindString(cmd))
		return execHit{
			sev: "LOW", conf: "LOW", cwe: "CWE-829",
			title:    "runs a standard third-party installer",
			enabled:  "runs a standard third-party installer from " + execOr(host, "a known installer host"),
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

	// 4. Fetching code/content from a non-allowlisted network destination. A host
	// that is a referenced secret's own service (e.g. a webhook POST) is normal.
	if execHasFetch(cmd) {
		for _, u := range ext {
			h := execHost(u)
			if execSecretToOwnService(cmd, h) {
				continue
			}
			return execHit{
				sev: "MEDIUM", conf: "MEDIUM", cwe: "CWE-829",
				enabled:  "downloads content from non-allowlisted host " + h,
				evidence: execTrim(cmd),
			}, true
		}
	}

	return execHit{}, false
}

func execTitle(prefix string, hit execHit) string {
	if hit.title != "" {
		return prefix + " " + hit.title
	}
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

// execShellRunsStdin lists interpreters that, when they appear at the receiving
// end of a pipe, execute piped stdin AS CODE. A POSIX-family shell always runs
// its standard input as commands.
var execShellRunsStdin = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "ash": true,
	"iex": true, // PowerShell Invoke-Expression: `... | iex` runs the piped string
}

// execScriptInterp lists language interpreters that run stdin as code only when
// invoked in a stdin-as-script mode (`python -`, `node -`, bare interpreter) and
// NOT when given a fixed program via -c/-e or a script file (then stdin is DATA).
var execScriptInterp = map[string]bool{
	"python": true, "python2": true, "python3": true,
	"node": true, "nodejs": true, "ruby": true, "perl": true, "php": true,
}

// execPipeToShell reports whether cmd pipes data into an interpreter that will
// execute that data AS CODE. It deliberately does NOT fire for pipe targets that
// read stdin as DATA (jq, grep, tee, `node -e '<fixed>'`, `python3 -c "<fixed>"`,
// `python file.py`, …) — only for a real remote-code-execution path.
func execPipeToShell(cmd string) bool {
	parts := strings.Split(cmd, "|")
	for i := 1; i < len(parts); i++ {
		if execInterpRunsStdin(strings.Fields(parts[i])) {
			return true
		}
	}
	return false
}

// execInterpRunsStdin decides whether the pipe-target command (its token fields)
// executes piped stdin as code.
func execInterpRunsStdin(fields []string) bool {
	if len(fields) == 0 {
		return false
	}
	tok := fields[0]
	args := fields[1:]
	if tok == "sudo" && len(fields) > 1 {
		tok = fields[1]
		args = fields[2:]
	}
	base := filepath.Base(tok)
	if execShellRunsStdin[base] {
		// A shell runs stdin as commands unless handed a fixed -c program.
		for _, a := range args {
			if a == "-c" {
				return false
			}
		}
		return true
	}
	if execScriptInterp[base] {
		for _, a := range args {
			switch {
			case a == "-c" || a == "-e":
				return false // fixed program supplied; stdin is data
			case a == "-":
				return true // explicit "read script from stdin"
			case strings.HasPrefix(a, "-"):
				continue // some other flag (e.g. -u, -E)
			default:
				return false // a script file argument; stdin is data
			}
		}
		return true // bare interpreter at a pipe end reads stdin as a script
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

// execInstallerMarkers identifies the canonical one-line installers that are
// standard developer practice. Matched as substrings of the command's URL text
// (host, or host+path for installers served from a shared code-host).
var execInstallerMarkers = []string{
	"rustup.rs",                        // rustup (incl. sh.rustup.rs)
	"raw.githubusercontent.com/nvm-sh", // nvm
	"raw.githubusercontent.com/homebrew",
	"get.brew.sh",    // Homebrew
	"bun.sh",         // bun
	"deno.land",      // deno
	"astral.sh/uv",   // uv
	"get.docker.com", // docker
}

// execIsInstaller reports whether cmd fetches from a canonical installer source.
func execIsInstaller(cmd string) bool {
	lc := strings.ToLower(cmd)
	for _, m := range execInstallerMarkers {
		if strings.Contains(lc, m) {
			return true
		}
	}
	return false
}

// execHasChecksum reports whether cmd verifies a downloaded artifact against a
// pinned checksum / signature (then even an installer is not a finding).
func execHasChecksum(cmd string) bool {
	lc := strings.ToLower(cmd)
	for _, p := range []string{
		"sha256sum", "sha512sum", "sha1sum", "shasum", "md5sum",
		"--checksum", "sha256:", "sha512:", "gpg --verify", "cosign verify",
	} {
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

// execSecretServiceHost maps a well-known secret/credential environment-variable
// name to the service host that secret legitimately authenticates to. A command
// that sends such a secret to its OWN service is normal operation, not
// exfiltration — only a mismatched destination is flagged.
var execSecretServiceHost = map[string]string{
	"DISCORD_WEBHOOK": "discord.com", "DISCORD_WEBHOOK_URL": "discord.com",
	"DISCORD_TOKEN": "discord.com", "DISCORD_BOT_TOKEN": "discord.com",
	"NPM_TOKEN": "registry.npmjs.org", "NPM_AUTH_TOKEN": "registry.npmjs.org",
	"NODE_AUTH_TOKEN": "registry.npmjs.org", "NPM_CONFIG_TOKEN": "registry.npmjs.org",
	"GH_TOKEN": "api.github.com", "GITHUB_TOKEN": "api.github.com",
	"GH_PAT": "api.github.com", "GITHUB_PAT": "api.github.com", "GH_ENTERPRISE_TOKEN": "api.github.com",
	"SLACK_TOKEN": "slack.com", "SLACK_WEBHOOK": "slack.com", "SLACK_WEBHOOK_URL": "slack.com",
	"SLACK_BOT_TOKEN": "slack.com", "SLACK_API_TOKEN": "slack.com",
	"STRIPE_SECRET_KEY": "stripe.com", "STRIPE_API_KEY": "stripe.com", "STRIPE_KEY": "stripe.com",
	"AWS_SECRET_ACCESS_KEY": "amazonaws.com", "AWS_ACCESS_KEY_ID": "amazonaws.com",
	"AWS_SESSION_TOKEN": "amazonaws.com",
	"TWILIO_AUTH_TOKEN": "twilio.com", "TWILIO_API_KEY": "twilio.com",
	"SENDGRID_API_KEY":   "sendgrid.com",
	"MAILGUN_API_KEY":    "mailgun.net",
	"TELEGRAM_BOT_TOKEN": "api.telegram.org", "TELEGRAM_TOKEN": "api.telegram.org",
	"DIGITALOCEAN_TOKEN": "digitalocean.com", "DO_TOKEN": "digitalocean.com",
	"HEROKU_API_KEY":       "heroku.com",
	"VERCEL_TOKEN":         "vercel.com",
	"NETLIFY_AUTH_TOKEN":   "netlify.com",
	"CLOUDFLARE_API_TOKEN": "cloudflare.com", "CF_API_TOKEN": "cloudflare.com", "CLOUDFLARE_TOKEN": "cloudflare.com",
	"DOCKERHUB_TOKEN": "docker.com", "DOCKER_TOKEN": "docker.com", "DOCKER_PASSWORD": "docker.com",
	"GITLAB_TOKEN": "gitlab.com", "CI_JOB_TOKEN": "gitlab.com",
	"PYPI_TOKEN": "pypi.org", "PYPI_API_TOKEN": "pypi.org", "TWINE_PASSWORD": "pypi.org",
	"CRATES_TOKEN": "crates.io", "CARGO_REGISTRY_TOKEN": "crates.io",
	"OPENAI_API_KEY":    "api.openai.com",
	"ANTHROPIC_API_KEY": "api.anthropic.com",
	"GCP_SA_KEY":        "googleapis.com", "GOOGLE_API_KEY": "googleapis.com", "GCP_CREDENTIALS": "googleapis.com",
	"AZURE_CLIENT_SECRET": "azure.com",
	"SENTRY_AUTH_TOKEN":   "sentry.io",
	"DATADOG_API_KEY":     "datadoghq.com", "DD_API_KEY": "datadoghq.com",
	"CODECOV_TOKEN":  "codecov.io",
	"FIREBASE_TOKEN": "firebaseio.com",
}

// execSecretNameRe captures the identifier of a referenced secret, in any of the
// common forms: ${{ secrets.NAME }}, $NAME, ${NAME}, env.NAME, process.env.NAME.
var execSecretNameRe = regexp.MustCompile(`(?:secrets\.|env\.|process\.env\.|\$\{?)([A-Z][A-Z0-9_]+)`)

// execSecretToOwnService reports whether a secret referenced in cmd legitimately
// belongs to destHost (so sending it there is not exfiltration).
func execSecretToOwnService(cmd, destHost string) bool {
	for _, m := range execSecretNameRe.FindAllStringSubmatch(cmd, -1) {
		svc, ok := execSecretServiceHost[m[1]]
		if !ok {
			continue
		}
		if destHost == svc || strings.HasSuffix(destHost, "."+svc) {
			return true
		}
	}
	return false
}

// execExfiltrates reports a secret/credential read combined with an off-host sink
// (a non-allowlisted URL or a raw network tool). A secret sent to its OWN service
// (per execSecretServiceHost) is not exfiltration. Returns the destination host.
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
		for _, u := range ext {
			h := execHost(u)
			if execSecretToOwnService(cmd, h) {
				continue // the secret's own service — legitimate
			}
			return h, true
		}
		// Every external destination is the secret's own service: not exfil.
		return "", false
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
	// Loopback is the machine itself (health checks, local dev servers), not
	// a remote code source or exfiltration destination.
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil {
		return ip.IsLoopback() // any other raw IP is never allowlisted
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
