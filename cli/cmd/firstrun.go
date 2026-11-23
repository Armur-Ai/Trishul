package cmd

import (
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/Armur-Ai/Trishul/internal/prgate"
)

// First-run experience (plan D0.6): running `trishul` with no subcommand in a
// repo does a quick hermetic built-in scan and prints a graded summary plus a
// "next steps" box, so a new user gets value in one command.

// runFirstRun scans dir with the built-in analyzers and prints a graded report
// to w. It is informational and returns 0 unless the scan itself errored.
func runFirstRun(dir string, w io.Writer) int {
	scan, err := prgate.ScanDir(dir)
	if err != nil {
		fmt.Fprintf(w, "scan failed: %v\n", err)
		return 1
	}
	fs := scan.Findings
	grade := prgate.Grade(fs)
	counts := prgate.Counts(fs)

	fmt.Fprintf(w, "\n  Trishul — quick scan of %s\n", dir)
	fmt.Fprintf(w, "  Grade: %s   (%d finding%s)\n", grade, len(fs), plural(len(fs)))
	if len(fs) > 0 {
		fmt.Fprintf(w, "  critical:%d high:%d medium:%d low:%d\n",
			counts["critical"], counts["high"], counts["medium"], counts["low"])
		fmt.Fprintln(w, "\n  Top findings:")
		for _, f := range topFindings(fs, 5) {
			fmt.Fprintf(w, "   • [%s] %s  %s:%d\n", f.Severity, f.RuleID, f.Path, f.Line)
		}
	} else {
		fmt.Fprintln(w, "  No issues found in a quick pass ✓")
	}

	fmt.Fprint(w, `
  Next steps:
   • trishul scan .            full scan with all profiles
   • trishul init github --pr  add the PR gate to this repo (your CI, your tokens)
   • trishul init rules        write secure-coding rules for your AI tools
   • trishul audit-mcp         audit your AI setup (MCP servers, tokens)
   • trishul mcp setup <client> let your agent call Trishul

`)
	return 0
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// topFindings returns up to n findings ordered by severity (critical first).
func topFindings(fs []prgate.Finding, n int) []prgate.Finding {
	out := make([]prgate.Finding, len(fs))
	copy(out, fs)
	sort.SliceStable(out, func(i, j int) bool {
		return prgate.Rank(out[i].Severity) > prgate.Rank(out[j].Severity)
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// maybeFirstRun is the rootCmd RunE: no args → first-run report; otherwise show
// help (cobra routes real subcommands before reaching here).
func maybeFirstRun() int {
	dir, err := os.Getwd()
	if err != nil {
		dir = "."
	}
	return runFirstRun(dir, os.Stdout)
}
