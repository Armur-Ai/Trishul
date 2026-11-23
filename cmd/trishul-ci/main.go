// Command trishul-ci is Trishul's hermetic CI / pull-request gate.
//
// It runs the built-in analyzers in-process (no server, no Redis, no external
// tools, never executes repository content), and in PR mode reports only the
// findings a change introduces:
//
//	trishul-ci --base origin/main --sarif trishul.sarif --markdown comment.md
//
// Exit codes: 0 = pass, 1 = gate failed (--fail-on), 2 = error.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Armur-Ai/Trishul/internal/prgate"
	common "github.com/Armur-Ai/Trishul/pkg/common"
	"github.com/rs/zerolog"
)

var (
	version = "dev"
	commit  = ""
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("trishul-ci", flag.ContinueOnError)
	var (
		base          = fs.String("base", "", "git ref to diff against (PR mode): only findings introduced since the merge base are reported")
		baselinePath  = fs.String("baseline", prgate.DefaultBaselineFile, "baseline file of accepted findings (relative to the scanned dir; ignored if missing)")
		writeBaseline = fs.Bool("write-baseline", false, "write all current findings to the baseline file and exit 0")
		sarifOut      = fs.String("sarif", "", "write SARIF 2.1.0 (non-baselined findings) to this file")
		jsonOut       = fs.String("json", "", "write the JSON report to this file")
		mdOut         = fs.String("markdown", "", "write the PR-comment markdown to this file")
		failOn        = fs.String("fail-on", "", "exit 1 if reported findings at or above this severity exist (critical|high|medium|low); empty = never fail")
		minSev        = fs.String("min-severity", "medium", "only report findings at or above this severity")
		linkBase      = fs.String("link-base", "", "prefix for file links in markdown, e.g. https://github.com/o/r/blob/<sha>/")
		includeTests  = fs.Bool("include-tests", false, "also report findings in test/fixture code (secrets and agent-security findings are always reported)")
		verbose       = fs.Bool("verbose", false, "show analyzer progress logs")
		showVersion   = fs.Bool("version", false, "print version and exit")
	)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), "Usage: trishul-ci [flags] [dir]\n\nTrishul PR gate: scan a checkout and report new security issues.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Printf("trishul-ci %s %s\n", version, commit)
		return 0
	}
	common.Version = version
	if !*verbose && os.Getenv("LOG_LEVEL") == "" {
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	}
	for name, v := range map[string]string{"fail-on": *failOn, "min-severity": *minSev} {
		if v != "" && !prgate.ValidSeverity(v) {
			_, _ = fmt.Fprintf(os.Stderr, "trishul-ci: invalid --%s %q (want critical|high|medium|low|info)\n", name, v)
			return 2
		}
	}

	dir := "."
	if fs.NArg() > 0 {
		dir = fs.Arg(0)
	}
	dir, _ = filepath.Abs(dir)
	start := time.Now()

	head, err := prgate.ScanDir(dir)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "trishul-ci: scan failed: %v\n", err)
		return 2
	}

	fopts := prgate.FilterOptions{IncludeTests: *includeTests}
	headFindings := prgate.Filter(head.Findings, dir, fopts)

	bp := *baselinePath
	if bp != "" && !filepath.IsAbs(bp) {
		bp = filepath.Join(dir, bp)
	}
	if *writeBaseline {
		if bp == "" {
			bp = filepath.Join(dir, prgate.DefaultBaselineFile)
		}
		if err := prgate.NewBaseline(headFindings).Save(bp); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "trishul-ci: write baseline: %v\n", err)
			return 2
		}
		fmt.Printf("Wrote %d finding(s) to %s. Commit it; these won't be reported again.\n", len(headFindings), bp)
		return 0
	}

	var bl *prgate.Baseline
	if bp != "" {
		if bl, err = prgate.LoadBaseline(bp); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "trishul-ci: %v\n", err)
			return 2
		}
	}
	current := bl.Apply(headFindings)

	rep := &prgate.Report{Mode: "full", Total: len(headFindings), FailOn: *failOn, LinkBase: *linkBase}
	for _, e := range head.Errors {
		rep.ScanErrors = append(rep.ScanErrors, e.Tool+": "+e.Message)
	}
	if *base != "" {
		ref := prgate.MergeBase(dir, *base, "HEAD")
		baseScan, err := prgate.ScanGitRef(dir, ref)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "trishul-ci: %v\n", err)
			return 2
		}
		intro, fixed := prgate.Diff(current, bl.Apply(prgate.Filter(baseScan.Findings, dir, fopts)))
		rep.Mode = "pr"
		rep.New = prgate.AtOrAbove(intro, *minSev)
		rep.Fixed = prgate.AtOrAbove(fixed, *minSev)
		rep.Existing = len(prgate.AtOrAbove(current, *minSev)) - len(rep.New)
		if rep.Existing < 0 {
			rep.Existing = 0
		}
	} else {
		rep.New = prgate.AtOrAbove(current, *minSev)
	}
	rep.Duration = time.Since(start)
	rep.Evaluate()

	md := rep.Markdown()
	if *sarifOut != "" {
		if err := writeJSON(*sarifOut, prgate.FilterSARIF(head.SARIF, current)); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "trishul-ci: write sarif: %v\n", err)
			return 2
		}
	}
	if *jsonOut != "" {
		if err := writeJSON(*jsonOut, rep); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "trishul-ci: write json: %v\n", err)
			return 2
		}
	}
	if *mdOut != "" {
		if err := os.WriteFile(*mdOut, []byte(md), 0o644); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "trishul-ci: write markdown: %v\n", err)
			return 2
		}
	}
	githubOutputs(rep, md)
	printText(rep)

	if rep.Failed {
		return 1
	}
	return 0
}

func writeJSON(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// githubOutputs writes step outputs and the job summary when running in
// GitHub Actions.
func githubOutputs(rep *prgate.Report, md string) {
	if p := os.Getenv("GITHUB_OUTPUT"); p != "" {
		c := prgate.Counts(rep.New)
		out := fmt.Sprintf("new-count=%d\ncritical-count=%d\nhigh-count=%d\nfailed=%t\n",
			len(rep.New), c["critical"], c["high"], rep.Failed)
		appendFile(p, out)
	}
	if p := os.Getenv("GITHUB_STEP_SUMMARY"); p != "" {
		appendFile(p, md+"\n")
	}
}

func appendFile(path, s string) {
	fh, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer func() { _ = fh.Close() }()
	_, _ = fh.WriteString(s)
}

func printText(rep *prgate.Report) {
	fmt.Printf("🔱 Trishul: %s\n", rep.Title())
	for _, f := range rep.New {
		loc := f.Path
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.Path, f.Line)
		}
		fmt.Printf("  [%s] %s %s\n      %s\n", strings.ToUpper(f.Severity), f.RuleID, loc, f.Message)
	}
	if len(rep.Fixed) > 0 {
		fmt.Printf("Fixed %d existing issue(s).\n", len(rep.Fixed))
	}
	if rep.Mode == "pr" && rep.Existing > 0 {
		fmt.Printf("%d pre-existing issue(s) not shown.\n", rep.Existing)
	}
	for _, e := range rep.ScanErrors {
		_, _ = fmt.Fprintf(os.Stderr, "warning: analyzer error: %s\n", e)
	}
	if rep.Failed {
		fmt.Printf("Gate FAILED: new findings at or above %q.\n", rep.FailOn)
	}
	fmt.Printf("Done in %.1fs.\n", rep.Duration.Seconds())
}
