package prgate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// DefaultBaselineFile is the conventional baseline location at repo root.
const DefaultBaselineFile = ".trishul-baseline.json"

// Baseline is an auditable, committed list of accepted findings. Findings in
// the baseline are not reported; a team adopts Trishul on an existing repo by
// baselining what is there today and gating only what comes next.
type Baseline struct {
	Version   int             `json:"version"`
	CreatedAt string          `json:"created_at"`
	Findings  []BaselineEntry `json:"findings"`
}

// BaselineEntry records one accepted finding. Rule/path/message are kept for
// human review of the file; matching uses only the fingerprint.
type BaselineEntry struct {
	Fingerprint string `json:"fingerprint"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Path        string `json:"path"`
	Message     string `json:"message"`
}

// NewBaseline builds a baseline from the given findings.
func NewBaseline(fs []Finding) *Baseline {
	b := &Baseline{Version: 1, CreatedAt: time.Now().UTC().Format(time.RFC3339), Findings: []BaselineEntry{}}
	for _, f := range fs {
		b.Findings = append(b.Findings, BaselineEntry{
			Fingerprint: f.Fingerprint, RuleID: f.RuleID, Severity: f.Severity, Path: f.Path, Message: f.Message,
		})
	}
	return b
}

// LoadBaseline reads a baseline file. A missing file returns (nil, nil).
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	return &b, nil
}

// Save writes the baseline as indented JSON.
func (b *Baseline) Save(path string) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// Apply removes baselined findings (multiset by fingerprint).
func (b *Baseline) Apply(fs []Finding) []Finding {
	if b == nil {
		return fs
	}
	var base []Finding
	for _, e := range b.Findings {
		base = append(base, Finding{Fingerprint: e.Fingerprint})
	}
	remaining, _ := Diff(fs, base)
	return remaining
}

// ScanGitRef scans repoDir as of ref using a temporary detached git worktree,
// leaving the caller's checkout untouched.
func ScanGitRef(repoDir, ref string) (*Scan, error) {
	tmp, err := os.MkdirTemp("", "trishul-base-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	wt := filepath.Join(tmp, "base")
	if out, err := git(repoDir, "worktree", "add", "--detach", "--force", wt, ref); err != nil {
		return nil, fmt.Errorf("check out base %q: %v: %s (does the checkout have history? use fetch-depth: 0)", ref, err, out)
	}
	defer func() { _, _ = git(repoDir, "worktree", "remove", "--force", wt) }()
	return ScanDir(wt)
}

// MergeBase returns the merge base of two refs, falling back to base itself.
func MergeBase(repoDir, base, head string) string {
	out, err := git(repoDir, "merge-base", base, head)
	if err != nil || strings.TrimSpace(out) == "" {
		return base
	}
	return strings.TrimSpace(out)
}

func git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// LoadBaselineAtRef reads the baseline as committed at ref (nil if absent).
// PR mode must use this rather than the head's file: otherwise a PR could
// suppress its own findings by adding them to the baseline.
func LoadBaselineAtRef(repoDir, ref, relPath string) (*Baseline, error) {
	out, err := exec.Command("git", "-C", repoDir, "show", ref+":"+filepath.ToSlash(relPath)).Output()
	if err != nil {
		return nil, nil // not present at ref
	}
	var b Baseline
	if err := json.Unmarshal(out, &b); err != nil {
		return nil, fmt.Errorf("parse baseline at %s: %w", ref, err)
	}
	return &b, nil
}
