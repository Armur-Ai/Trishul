// Package engine provides an in-process entry point for running a local scan
// without the HTTP server or Redis. It is the basis for the embedded
// `trishul scan .` path and is already used by the MCP server.
//
// The scan target is treated as read-only (see pkg.SafeRemoveAll / the
// managed-path guard); this package never mutates the directory it scans.
package engine

import (
	"github.com/Armur-Ai/Trishul/internal/tasks"
)

// Result is the outcome of an in-process scan: the categorized findings plus
// the per-tool scan errors (including tools that were skipped because they are
// not installed — never conflate a skipped tool with a clean result).
type Result struct {
	Findings   map[string]interface{}
	ScanErrors []tasks.ScanError
}

// ScanLocal runs a standard scan of a local directory in-process — no server,
// no Redis, no task queue. An empty language auto-detects. The target is
// read-only.
func ScanLocal(dir, language string) (*Result, error) {
	findings, scanErrors, err := tasks.RunSimpleScanLocal(dir, language)
	if err != nil {
		return nil, err
	}
	return &Result{Findings: findings, ScanErrors: scanErrors}, nil
}
