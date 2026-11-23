package agenthook

import (
	"os"
	"path/filepath"

	"github.com/Armur-Ai/Trishul/internal/fileclass"
	"github.com/Armur-Ai/Trishul/internal/suppress"
)

// ScanFunc runs the built-in analyzers over a directory (read-only) and returns
// findings with repo-relative paths. The production implementation wraps
// internal/prgate.ScanDir; tests inject a deterministic stub.
type ScanFunc func(dir string) ([]Finding, error)

// BashFunc classifies a single shell command and returns the dangerous
// execution paths it contains. The production implementation reuses the
// internal/agentsec AGENT-EXEC rules; tests inject a stub.
type BashFunc func(command, workspace string) []Finding

// scanFile performs an incremental, single-file scan of content as it would
// appear at relPath. It writes the content into a throwaway directory (never
// the real tree, never executing anything) and runs scan over just that file,
// so only analyzers relevant to the file's kind do any work.
//
// Files that cannot contain real logic or agent-surface instructions
// (vendored, generated, minified, lockfiles, localized/doc text) are skipped
// outright — classification comes from internal/fileclass.
func scanFile(scan ScanFunc, tmpRoot, relPath string, content []byte) ([]Finding, error) {
	if !fileclass.Classify(relPath, content).IsCodeLike() {
		return nil, nil
	}
	if err := os.MkdirAll(tmpRoot, 0o700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(tmpRoot, "scan-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	dst := filepath.Join(dir, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(dst, content, 0o600); err != nil {
		return nil, err
	}

	fs, err := scan(dir)
	if err != nil {
		return nil, err
	}
	// Keep only findings for the file we wrote (defensive: the scan dir holds
	// just this one file, but a correlated/aggregate finding could differ).
	out := fs[:0]
	for _, f := range fs {
		if f.Path == "" || f.Path == relPath {
			f.Path = relPath
			out = append(out, f)
		}
	}
	return out, nil
}

// applySuppressions drops findings covered by an inline suppression marker in
// content (internal/suppress) and any rule excluded by config.
func applySuppressions(fs []Finding, relPath string, content []byte, cfg Config) []Finding {
	idx := suppress.NewIndex(suppress.ScanFile(relPath, content))
	kept := make([]Finding, 0, len(fs))
	for _, f := range fs {
		if cfg.excludes(f.RuleID) {
			continue
		}
		if _, ok := idx.Suppressed(f.Path, f.Line, f.RuleID); ok {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}
