package agentsec

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Component 4: MCP server & tool trust.
//
// Model Context Protocol (MCP) servers are external processes/endpoints an AI
// agent is told to launch and trust. A malicious or careless MCP config entry is
// a supply-chain foothold: it can pull unpinned/remote code onto the dev's
// machine, exfiltrate embedded secrets, or register an unvetted server that the
// agent then drives. This analyzer parses MCP config files (read-only, never
// launching anything) and flags the untrusted patterns.
//
//	AGENT-MCP-001  unpinned auto-install runner (npx -y / uvx / bunx, no version)
//	AGENT-MCP-002  server fetches + runs remote code (curl|wget to shell / URL arg)
//	AGENT-MCP-003  secret embedded in MCP config (reported REDACTED only)
//	AGENT-MCP-004  newly-configured server — review its trust (baseline)
func init() { register(scanMCPTrust) }

const (
	mcpTrustBoundary = "untrusted config change -> agent tool/permission scope"
	mcpWorkflow      = "an AI agent registers MCP servers"
)

// mcpPipeShellRe matches a remote fetch piped into an interpreter, e.g.
// `curl https://x.sh | bash` or `wget -qO- url | sh`.
var mcpPipeShellRe = regexp.MustCompile(`(?i)(curl|wget)\b[^|]*\|\s*(sh|bash|zsh|dash|python3?|node|ruby|perl)\b`)

// mcpSecretKeyRe matches config keys whose values are expected to be secrets.
var mcpSecretKeyRe = regexp.MustCompile(`(?i)(^|[_\-])(api[_\-]?key|apikey|secret|password|passwd|token|access[_\-]?key|client[_\-]?secret|bearer|private[_\-]?key|auth[_\-]?token|pat)([_\-]|$)`)

// mcpSecretValRe matches values that look like real credentials regardless of key.
var mcpSecretValRe = []*regexp.Regexp{
	regexp.MustCompile(`sk-[A-Za-z0-9]{16,}`),                           // OpenAI / generic
	regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{16,}`),                    // Anthropic
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`),                    // GitHub tokens
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9\-]{10,}`),                 // Slack
	regexp.MustCompile(`AKIA[0-9A-Z]{12,}`),                             // AWS access key id
	regexp.MustCompile(`AIza[0-9A-Za-z_\-]{30,}`),                       // Google API key
	regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.`), // JWT
}

func scanMCPTrust(dir string) ([]AgentFinding, error) {
	var out []AgentFinding
	err := WalkFiles(dir, mcpMatch, func(path string, content []byte) {
		servers, key := mcpExtractServers(content)
		if len(servers) == 0 {
			return // not an MCP config
		}
		rel := Rel(dir, path)
		lines := SplitLines(content)
		for _, name := range mcpSortedKeys(servers) {
			out = append(out, mcpInspectServer(rel, lines, name, servers[name], key)...)
		}
	})
	return out, err
}

// mcpMatch selects candidate JSON files; the content check in mcpExtractServers
// confirms whether a given file is actually an MCP config.
func mcpMatch(name, path string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".json")
}

// mcpExtractServers returns the server map (name -> raw def) and which top-level
// key held it ("mcpServers" or "servers"), or nil if the file is not MCP-shaped.
func mcpExtractServers(content []byte) (map[string]json.RawMessage, string) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(content, &top); err != nil {
		return nil, ""
	}
	for _, key := range []string{"mcpServers", "servers"} {
		raw, ok := top[key]
		if !ok {
			continue
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil || len(m) == 0 {
			continue // e.g. an array named "servers" in some unrelated config
		}
		// Confirm MCP shape: at least one entry is an object with a server field.
		if mcpLooksLikeServers(m) {
			return m, key
		}
	}
	return nil, ""
}

func mcpLooksLikeServers(m map[string]json.RawMessage) bool {
	for _, raw := range m {
		var def map[string]json.RawMessage
		if json.Unmarshal(raw, &def) != nil {
			continue
		}
		for _, f := range []string{"command", "url", "args", "type", "env"} {
			if _, ok := def[f]; ok {
				return true
			}
		}
	}
	return false
}

type mcpServer struct {
	Command string
	Args    []string
	URL     string
}

func mcpInspectServer(file string, lines []string, name string, raw json.RawMessage, topKey string) []AgentFinding {
	var def mcpServer
	// Tolerate shapes: command may be string, args []string, url string.
	var probe struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
		URL     string   `json:"url"`
		Type    string   `json:"type"`
	}
	_ = json.Unmarshal(raw, &probe)
	def.Command, def.Args, def.URL = probe.Command, probe.Args, probe.URL

	nameLine := mcpLine(lines, 1, fmt.Sprintf("%q", name))
	var out []AgentFinding

	tokens := append(mcpTokenize(def.Command), def.Args...)

	// AGENT-MCP-002: remote code fetch + run.
	joined := strings.ToLower(def.Command + " " + strings.Join(def.Args, " "))
	prog := mcpProg(tokens)
	if mcpPipeShellRe.MatchString(joined) || prog == "curl" || prog == "wget" {
		out = append(out, AgentFinding{
			CheckID:          "AGENT-MCP-002",
			Title:            "MCP server fetches and runs remote code",
			Severity:         "HIGH",
			Confidence:       "HIGH",
			EntryPoint:       file,
			TrustBoundary:    mcpTrustBoundary,
			AffectedWorkflow: mcpWorkflow,
			EnabledAction:    "launching this server downloads and executes remote code on the developer machine",
			File:             file,
			Line:             nameLine,
			Evidence:         []string{mcpTrim(fmt.Sprintf("%s: %s", name, strings.TrimSpace(def.Command+" "+strings.Join(def.Args, " "))))},
			Limitations:      "static read of config; the fetched payload is not retrieved or executed",
			Remediation:      "vendor and pin the server; never pipe curl/wget into a shell from MCP config",
			CWE:              "CWE-829",
		})
	}

	// AGENT-MCP-001: unpinned auto-install runner.
	if runner, pkg, ok := mcpUnpinnedRunner(prog, tokens); ok {
		out = append(out, AgentFinding{
			CheckID:          "AGENT-MCP-001",
			Title:            "MCP server launched via unpinned package runner",
			Severity:         "HIGH",
			Confidence:       "HIGH",
			EntryPoint:       file,
			TrustBoundary:    mcpTrustBoundary,
			AffectedWorkflow: mcpWorkflow,
			EnabledAction:    fmt.Sprintf("%s auto-installs %q at the floating latest version each launch", runner, pkg),
			File:             file,
			Line:             nameLine,
			Evidence:         []string{mcpTrim(fmt.Sprintf("%s: %s", name, strings.TrimSpace(def.Command+" "+strings.Join(def.Args, " "))))},
			Limitations:      "unpinned does not prove malice; it removes the guarantee that the vetted version runs",
			Remediation:      fmt.Sprintf("pin an exact version (e.g. %s@<x.y.z>) and verify its integrity", pkg),
			CWE:              "CWE-829",
		})
	}

	// AGENT-MCP-003: embedded secrets (reported REDACTED only).
	for _, s := range mcpFindSecrets(raw) {
		line := mcpLine(lines, nameLine, fmt.Sprintf("%q", s.lastKey))
		out = append(out, AgentFinding{
			CheckID:          "AGENT-MCP-003",
			Title:            "Secret embedded in MCP server config",
			Severity:         "HIGH",
			Confidence:       s.confidence,
			EntryPoint:       file,
			TrustBoundary:    mcpTrustBoundary,
			AffectedWorkflow: mcpWorkflow,
			EnabledAction:    "a committed credential is handed to the MCP server process and exposed to anyone with repo access",
			File:             file,
			Line:             line,
			Evidence:         []string{mcpRedact(s.path, s.value)},
			Limitations:      "value is redacted; verify and rotate the credential out of band",
			Remediation:      "move the secret to an environment variable / secret store; rotate the exposed value",
			CWE:              "CWE-798",
		})
	}

	// AGENT-MCP-004: baseline trust review. A passive dir scan cannot see a PR
	// diff, so it cannot prove a server is "newly added"; it instead surfaces the
	// servers that most warrant a trust review and that the specific checks above
	// did not already flag — remote/networked servers whose code the agent will
	// connect to. An ordinary pinned local server stays clean.
	if len(out) == 0 && mcpIsRemote(def, tokens) {
		transport := strings.TrimSpace(def.Command + " " + strings.Join(def.Args, " "))
		if transport == "" {
			transport = def.URL
		}
		out = append(out, AgentFinding{
			CheckID:          "AGENT-MCP-004",
			Title:            "Remote MCP server configured — review its trust",
			Severity:         "MEDIUM",
			Confidence:       "LOW",
			EntryPoint:       file,
			TrustBoundary:    mcpTrustBoundary,
			AffectedWorkflow: mcpWorkflow,
			EnabledAction:    "the agent will connect to this remote server and expose its tools to the model",
			File:             file,
			Line:             nameLine,
			Evidence:         []string{mcpTrim(fmt.Sprintf("%s (%s): %s", name, topKey, transport))},
			Limitations:      "passive scan cannot judge the server's provenance or whether it is newly added; this is a review prompt, not a proven vulnerability",
			Remediation:      "confirm this server is expected, from a trusted author, and scoped to least privilege",
			CWE:              "CWE-829",
		})
	}
	return out
}

// mcpIsRemote reports whether the server reaches off-machine: an HTTP/SSE url
// transport, or an http(s) URL embedded in the launch command.
func mcpIsRemote(def mcpServer, tokens []string) bool {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(def.URL)), "http") {
		return true
	}
	for _, t := range tokens {
		lt := strings.ToLower(t)
		if strings.Contains(lt, "http://") || strings.Contains(lt, "https://") {
			return true
		}
	}
	return false
}

// mcpUnpinnedRunner reports (runner, package, true) when the server is launched
// with an auto-installing runner (npx -y/--yes, uvx, bunx, pnpx) at a floating
// (unpinned) version.
func mcpUnpinnedRunner(prog string, tokens []string) (string, string, bool) {
	switch prog {
	case "npx", "pnpx":
		if !mcpHasFlag(tokens, "-y", "--yes") {
			return "", "", false
		}
	case "uvx", "bunx":
		// these always fetch+run without a persisted lock
	default:
		return "", "", false
	}
	pkg := mcpPackageArg(tokens)
	if pkg == "" || mcpIsPinned(pkg) {
		return "", "", false
	}
	return prog, pkg, true
}

// mcpPackageArg returns the first non-flag positional argument (the package).
func mcpPackageArg(tokens []string) string {
	for i := 1; i < len(tokens); i++ {
		t := tokens[i]
		if strings.HasPrefix(t, "-") {
			continue
		}
		return t
	}
	return ""
}

// mcpIsPinned reports whether a package spec carries a concrete version pin.
// Floating tags (latest/next/beta/...) count as unpinned.
func mcpIsPinned(pkg string) bool {
	s := pkg
	s = strings.TrimPrefix(s, "@") // scoped package: skip the scope separator
	at := strings.Index(s, "@")
	if at < 0 {
		return false
	}
	ver := strings.ToLower(s[at+1:])
	if ver == "" {
		return false
	}
	switch ver {
	case "latest", "next", "beta", "canary", "alpha", "rc", "dev", "nightly":
		return false
	}
	// A concrete version starts with a digit or a leading v/^/~ + digit.
	ver = strings.TrimLeft(ver, "v^~>=< ")
	return len(ver) > 0 && ver[0] >= '0' && ver[0] <= '9'
}

type mcpSecret struct {
	path       string // full key path, for context
	lastKey    string
	value      string
	confidence string
}

// mcpFindSecrets walks the server definition and returns embedded credentials.
func mcpFindSecrets(raw json.RawMessage) []mcpSecret {
	var v interface{}
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	var found []mcpSecret
	mcpWalkSecrets("", "", v, &found)
	return found
}

func mcpWalkSecrets(path, key string, v interface{}, found *[]mcpSecret) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			np := k
			if path != "" {
				np = path + "." + k
			}
			mcpWalkSecrets(np, k, val, found)
		}
	case []interface{}:
		for _, val := range t {
			mcpWalkSecrets(path, key, val, found)
		}
	case string:
		if conf := mcpSecretConfidence(key, t); conf != "" {
			*found = append(*found, mcpSecret{path: path, lastKey: key, value: t, confidence: conf})
		}
	}
}

// mcpSecretConfidence returns "" (not a secret), or a confidence level.
func mcpSecretConfidence(key, val string) string {
	if mcpIsPlaceholder(val) {
		return ""
	}
	for _, re := range mcpSecretValRe {
		if re.MatchString(val) {
			return "HIGH" // value itself is a recognizable credential
		}
	}
	if len(val) >= 8 && mcpSecretKeyRe.MatchString(key) {
		return "MEDIUM" // secret-looking key with a literal value
	}
	return ""
}

// mcpIsPlaceholder skips env references and obvious non-secrets.
func mcpIsPlaceholder(val string) bool {
	v := strings.TrimSpace(val)
	if v == "" {
		return true
	}
	if strings.HasPrefix(v, "$") || strings.Contains(v, "${") {
		return true // ${TOKEN} / $TOKEN references
	}
	if strings.HasPrefix(v, "<") && strings.HasSuffix(v, ">") {
		return true // <your-token-here>
	}
	lower := strings.ToLower(v)
	for _, p := range []string{"changeme", "example", "redacted", "placeholder", "your-", "xxxx", "****"} {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// mcpRedact produces a leak-free preview: key path plus the length only.
func mcpRedact(path, val string) string {
	if path == "" {
		path = "<value>"
	}
	return fmt.Sprintf("%s = [REDACTED secret, %d chars]", path, len(val))
}

func mcpTokenize(s string) []string {
	return strings.Fields(s)
}

func mcpProg(tokens []string) string {
	if len(tokens) == 0 {
		return ""
	}
	return strings.ToLower(filepath.Base(tokens[0]))
}

func mcpHasFlag(tokens []string, flags ...string) bool {
	for _, t := range tokens {
		for _, f := range flags {
			if t == f {
				return true
			}
		}
	}
	return false
}

func mcpTrim(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > 160 {
		return s[:157] + "..."
	}
	return s
}

// mcpLine returns the 1-based line number of the first line at/after `from`
// containing needle, else `from`.
func mcpLine(lines []string, from int, needle string) int {
	start := from - 1
	if start < 0 {
		start = 0
	}
	for i := start; i < len(lines); i++ {
		if strings.Contains(lines[i], needle) {
			return i + 1
		}
	}
	// fall back to a full scan from the top
	for i := 0; i < len(lines); i++ {
		if strings.Contains(lines[i], needle) {
			return i + 1
		}
	}
	if from < 1 {
		return 1
	}
	return from
}

func mcpSortedKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// simple insertion sort to avoid an extra import for determinism
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	return keys
}
