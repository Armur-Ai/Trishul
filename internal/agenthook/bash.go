package agenthook

import (
	"path/filepath"
	"regexp"
	"strings"
)

// bashInput is the permissive view of tool_input for the Bash tool.
type bashInput struct {
	Command string `json:"command"`
}

// segment splitters: command separators that start a new simple command.
var bashSegSplit = regexp.MustCompile(`&&|\|\||[;\n]`)

// splitBashSegments breaks a compound command line into simple-command segments
// (split on ; && || and newlines). Pipes are intentionally kept intact so the
// AGENT-EXEC pipe-to-shell rules can see "curl … | bash" as one command.
func splitBashSegments(command string) []string {
	parts := bashSegSplit.Split(command, -1)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// dangerousRmRf reports a finding when the command recursively force-removes a
// path outside the workspace (root, home, an absolute path not under the
// workspace, or one that escapes it via ".."). This complements the AGENT-EXEC
// rules, which do not cover destructive filesystem commands.
func dangerousRmRf(command, workspace string) (Finding, bool) {
	for _, seg := range splitBashSegments(command) {
		fields := strings.Fields(seg)
		rmAt := -1
		for i, f := range fields {
			if f == "rm" || strings.HasSuffix(f, "/rm") {
				rmAt = i
				break
			}
		}
		if rmAt < 0 {
			continue
		}
		var recursive, force bool
		var targets []string
		for _, tok := range fields[rmAt+1:] {
			switch {
			case strings.HasPrefix(tok, "--"):
				if tok == "--recursive" {
					recursive = true
				}
				if tok == "--force" {
					force = true
				}
			case strings.HasPrefix(tok, "-"):
				if strings.ContainsRune(tok, 'r') || strings.ContainsRune(tok, 'R') {
					recursive = true
				}
				if strings.ContainsRune(tok, 'f') {
					force = true
				}
			default:
				targets = append(targets, tok)
			}
		}
		if !(recursive && force) {
			continue
		}
		for _, t := range targets {
			if pathOutsideWorkspace(t, workspace) {
				return Finding{
					RuleID:   "AGENT-BASH-RMRF",
					Severity: "high",
					Message:  "recursive force-remove (rm -rf) targets a path outside the workspace: " + t,
					Fix:      "Scope destructive removals to a path inside the workspace; never rm -rf an absolute, home, or parent-escaping path.",
				}, true
			}
		}
	}
	return Finding{}, false
}

// pathOutsideWorkspace reports whether a destructive target is clearly outside
// the workspace root.
func pathOutsideWorkspace(arg, workspace string) bool {
	arg = strings.Trim(arg, `"'`)
	if arg == "" {
		return false
	}
	if arg == "/" || arg == "/*" || arg == "~" || strings.HasPrefix(arg, "~/") {
		return true
	}
	if strings.Contains(arg, "$HOME") || strings.Contains(arg, "${HOME") {
		return true
	}
	// Parent-escaping relative path.
	cleaned := filepath.ToSlash(filepath.Clean(arg))
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return true
	}
	if filepath.IsAbs(arg) {
		if workspace == "" {
			return true // cannot verify containment
		}
		abs := filepath.Clean(arg)
		ws := filepath.Clean(workspace)
		if abs == ws {
			return false
		}
		rel, err := filepath.Rel(ws, abs)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
		return false
	}
	return false
}
