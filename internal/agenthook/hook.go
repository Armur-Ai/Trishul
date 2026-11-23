// Package agenthook implements Trishul's Claude Code hook engine: it guards an
// AI coding agent's edits and commands in real time by reading a single Claude
// Code hook event from stdin and emitting the exit-code / stderr contract the
// agent understands.
//
// Design guarantees (hermetic):
//   - It NEVER executes the edited code, repository scripts, or agent commands.
//     Every input — edited file content and shell command text alike — is
//     treated as DATA and only ever read.
//   - It makes no outward network calls.
//   - It never fails the agent's turn over its own errors (bad config, unreadable
//     cache, scan failure): on any internal problem it exits 0 silently.
//
// Event handling:
//
//	PostToolUse Write/Edit/MultiEdit/NotebookEdit
//	    Incrementally scans just the touched file (analyzers chosen by file
//	    kind), diffs against the pre-edit state so only NEW findings surface,
//	    honors inline suppressions, and blocks (exit 2) when a new finding is at
//	    or above the configured severity. A finding re-reported too often in a
//	    session is downgraded to a warning (loop breaker).
//	PreToolUse Bash
//	    Flags dangerous commands (remote pipe-to-shell, secret exfiltration,
//	    rm -rf outside the workspace) reusing the AGENT-EXEC rules. Mode is
//	    warn (report, allow) or block (report, exit 2).
//	Stop / SessionEnd
//	    Prints "Trishul checked N edits, blocked M issues".
package agenthook

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

const (
	exitOK    = 0
	exitBlock = 2

	// loopLimit is how many times a given finding (by rule + message) may be
	// blocked on in a session before it is downgraded to a warning.
	loopLimit = 3
)

// editTools are the PostToolUse tools the hook inspects.
var editTools = map[string]bool{
	"Write": true, "Edit": true, "MultiEdit": true, "NotebookEdit": true,
}

// Options configures Run. The zero value is production-ready; tests override the
// scanners (for determinism) and TmpRoot (for isolation).
type Options struct {
	Scanner     ScanFunc // nil → prgate-backed built-in scan
	BashScanner BashFunc // nil → agentsec-backed AGENT-EXEC classifier
	TmpRoot     string   // nil/"" → <os.TempDir()>/trishul-hook
}

func (o Options) withDefaults() Options {
	if o.Scanner == nil {
		o.Scanner = defaultScan
	}
	if o.BashScanner == nil {
		o.BashScanner = defaultBashScan
	}
	if o.TmpRoot == "" {
		o.TmpRoot = filepath.Join(os.TempDir(), "trishul-hook")
	}
	return o
}

// hookInput is the permissive view of a Claude Code hook event.
type hookInput struct {
	SessionID     string          `json:"session_id"`
	CWD           string          `json:"cwd"`
	HookEventName string          `json:"hook_event_name"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
}

// Run reads one hook event from stdin and returns the process exit code. It is
// the single entry point used by the `trishul hook claude-code` command.
func Run(stdin io.Reader, stdout, stderr io.Writer, opts Options) int {
	opts = opts.withDefaults()

	data, err := io.ReadAll(stdin)
	if err != nil {
		return exitOK // never fail the hook over I/O
	}
	var in hookInput
	if err := json.Unmarshal(data, &in); err != nil {
		return exitOK // tolerate malformed payloads
	}

	cfg := LoadConfig(in.CWD)

	switch in.HookEventName {
	case "PreToolUse":
		if in.ToolName == "Bash" {
			return handleBash(in, cfg, opts, stderr)
		}
		return exitOK
	case "PostToolUse":
		if editTools[in.ToolName] {
			return handleEdit(in, cfg, opts, stderr)
		}
		return exitOK
	case "Stop", "SessionEnd":
		return handleSummary(in, opts, stdout)
	default:
		return exitOK
	}
}

// handleEdit scans the touched file, diffs against its pre-edit state, and
// decides whether to block.
func handleEdit(in hookInput, cfg Config, opts Options, stderr io.Writer) int {
	ei := decodeEditInput(in.ToolInput)
	abs, rel, ok := resolvePath(in.CWD, ei)
	if !ok {
		return exitOK
	}

	sessPath := sessionPath(opts.TmpRoot, in.SessionID)
	sess := loadSession(sessPath)
	sess.Edits++ // this edit is "checked" even if nothing is found
	defer sess.save(sessPath)

	post, err := os.ReadFile(abs)
	if err != nil {
		return exitOK // file gone / unreadable: nothing to scan
	}

	head, err := scanFile(opts.Scanner, opts.TmpRoot, rel, post)
	if err != nil {
		return exitOK // scan failure must not fail the hook
	}
	head = applySuppressions(head, rel, post, cfg)

	// Baseline = everything known before this edit: the session's last-seen
	// fingerprints for this file, plus (when reconstructable) the pre-edit
	// content's findings.
	base := sess.baseline(rel)
	if pre, havePre := reconstructPre(in.ToolName, ei, post); havePre {
		preFindings, err := scanFile(opts.Scanner, opts.TmpRoot, rel, pre)
		if err == nil {
			preFindings = applySuppressions(preFindings, rel, pre, cfg)
			for fp := range fingerprintSet(preFindings) {
				base[fp] = true
			}
		}
	}

	// New = head findings absent from the baseline.
	var news []Finding
	for _, f := range head {
		if !base[f.fingerprint()] {
			news = append(news, f)
		}
	}

	// Update the per-file baseline for the next edit before deciding, so the
	// cache reflects the current state regardless of the outcome.
	sess.setFile(rel, head)

	// Severity gate + loop breaker.
	var blockable, warnings []Finding
	for _, f := range news {
		if rank(f.Severity) < rank(cfg.BlockOn) {
			continue // below threshold: ignore silently
		}
		key := loopKey(f)
		if sess.Reports[key] >= loopLimit {
			warnings = append(warnings, f) // re-reported too often: downgrade
			continue
		}
		sess.Reports[key]++
		blockable = append(blockable, f)
	}
	sortFindings(blockable)
	sortFindings(warnings)

	if len(blockable) > 0 {
		sess.Blocked += len(blockable)
		io.WriteString(stderr, blockMessage(blockable, cfg.BlockOn))
		return exitBlock
	}
	if len(warnings) > 0 {
		io.WriteString(stderr, warnMessage(warnings))
		return exitOK
	}
	return exitOK
}

// handleBash classifies a shell command before it runs.
func handleBash(in hookInput, cfg Config, opts Options, stderr io.Writer) int {
	if cfg.BashGuard == "off" {
		return exitOK
	}
	var bi bashInput
	if err := json.Unmarshal(in.ToolInput, &bi); err != nil || bi.Command == "" {
		return exitOK
	}

	findings := opts.BashScanner(bi.Command, in.CWD)
	if rf, ok := dangerousRmRf(bi.Command, in.CWD); ok {
		findings = append(findings, rf)
	}
	findings = dedupeByFingerprint(findings)
	// Respect rule excludes here too.
	kept := findings[:0]
	for _, f := range findings {
		if !cfg.excludes(f.RuleID) {
			kept = append(kept, f)
		}
	}
	findings = kept
	sortFindings(findings)

	if len(findings) == 0 {
		return exitOK
	}
	if cfg.BashGuard == "block" {
		io.WriteString(stderr, bashBlockMessage(findings))
		return exitBlock
	}
	io.WriteString(stderr, bashWarnMessage(findings))
	return exitOK
}

// handleSummary prints the session tally on Stop / SessionEnd.
func handleSummary(in hookInput, opts Options, stdout io.Writer) int {
	sessPath := sessionPath(opts.TmpRoot, in.SessionID)
	sess := loadSession(sessPath)
	io.WriteString(stdout, summaryMessage(sess.Edits, sess.Blocked))
	if in.HookEventName == "SessionEnd" {
		_ = os.Remove(sessPath) // tidy up at end of session
	}
	return exitOK
}

// loopKey identifies a finding independent of file/line, so "the same finding"
// re-reported across edits or files is counted together by the loop breaker.
func loopKey(f Finding) string {
	return f.RuleID + "\x00" + f.Message
}

func dedupeByFingerprint(fs []Finding) []Finding {
	seen := map[string]bool{}
	out := fs[:0]
	for _, f := range fs {
		fp := f.fingerprint()
		if seen[fp] {
			continue
		}
		seen[fp] = true
		out = append(out, f)
	}
	return out
}
