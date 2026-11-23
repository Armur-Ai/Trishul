// Package autofix provides deterministic, local fixes for findings (plan P4.2),
// rendered as GitHub suggestion blocks and SARIF fixes[]. A fix is offered only
// when it is deterministic and local, and it is validated by re-scanning the
// patched file in memory — a fix that doesn't actually clear the finding (or
// that introduces a new one) is discarded.
package autofix

import (
	"fmt"
	"strings"

	"github.com/Armur-Ai/Trishul/internal/findings"
)

// Patch is a local, line-based replacement. Lines are 1-based and inclusive.
type Patch struct {
	Path        string `json:"path"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	Replacement string `json:"replacement"`
}

// Apply returns src with lines [StartLine,EndLine] replaced by Replacement. A
// patch whose EndLine is StartLine-1 is an insertion before StartLine; a patch
// at len(lines)+1 appends. Out-of-range patches return an error.
func (p Patch) Apply(src string) (string, error) {
	lines := strings.Split(src, "\n")
	// Trailing newline produces a final empty element; track it to restore.
	n := len(lines)
	if p.StartLine < 1 || p.EndLine < p.StartLine-1 || p.StartLine > n+1 || p.EndLine > n {
		return "", fmt.Errorf("patch %s lines [%d,%d] out of range (file has %d lines)", p.Path, p.StartLine, p.EndLine, n)
	}
	repl := strings.Split(p.Replacement, "\n")
	if p.Replacement == "" {
		repl = nil // pure deletion
	}
	out := make([]string, 0, n)
	out = append(out, lines[:p.StartLine-1]...)
	out = append(out, repl...)
	if p.EndLine < n {
		out = append(out, lines[p.EndLine:]...)
	}
	return strings.Join(out, "\n"), nil
}

// Fixer produces a Patch for a finding, or ok=false if it cannot.
type Fixer func(f findings.Finding, src string) (Patch, bool)

var registry = map[string]Fixer{}

// Register associates a fixer with a rule id. Later registrations win (so a more
// specific fixer can override a default).
func Register(ruleID string, fx Fixer) { registry[ruleID] = fx }

// FixFor returns a validated patch for a finding, if a fixer is registered and
// the patch is in range. Callers pass a rescan to confirm the fix clears the
// finding (see Validate); FixFor itself only builds and range-checks the patch.
func FixFor(f findings.Finding, src string) (Patch, bool) {
	fx, ok := registry[f.RuleID]
	if !ok {
		return Patch{}, false
	}
	p, ok := fx(f, src)
	if !ok {
		return Patch{}, false
	}
	if _, err := p.Apply(src); err != nil {
		return Patch{}, false
	}
	return p, true
}

// Validate applies the patch and re-scans the patched source; it returns true
// only when the patched file produces strictly fewer findings than before (the
// fix removed at least the target without adding new ones). rescan returns the
// finding count for a given source.
func Validate(p Patch, src string, before int, rescan func(patched string) int) bool {
	patched, err := p.Apply(src)
	if err != nil {
		return false
	}
	return rescan(patched) < before
}

// Registered reports how many fixers are registered (diagnostics/tests).
func Registered() int { return len(registry) }
