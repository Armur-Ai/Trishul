// Command trishul-bench measures rule precision against a labeled corpus (P0.3).
//
// Subcommands:
//
//	trishul-bench report --labels labels.jsonl [--rules R1,R2] [--md out.md] [--json out.json]
//	    Compute per-rule precision from an existing labels file.
//
//	trishul-bench scan --dir DIR --labels labels.jsonl [--rules ...] [--md ...] [--json ...]
//	    Scan DIR with the built-in analyzers, join findings to labels, and report
//	    precision over the labeled findings plus the count of unlabeled findings
//	    (the labeling queue).
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/Armur-Ai/Trishul/internal/precision"
	"github.com/Armur-Ai/Trishul/internal/prgate"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "report":
		err = runReport(os.Args[2:])
	case "scan":
		err = runScan(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "trishul-bench:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `trishul-bench — rule precision harness

usage:
  trishul-bench report --labels FILE [--rules R1,R2] [--md FILE] [--json FILE]
  trishul-bench scan   --dir DIR --labels FILE [--rules R1,R2] [--md FILE] [--json FILE]
`)
}

// flags is a tiny hand-rolled parser so each subcommand shares option handling.
type flags struct {
	labels, dir, rules, md, json string
}

func parse(args []string) (flags, error) {
	var f flags
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("missing value for %s", a)
			}
			i++
			return args[i], nil
		}
		var err error
		switch a {
		case "--labels":
			f.labels, err = next()
		case "--dir":
			f.dir, err = next()
		case "--rules":
			f.rules, err = next()
		case "--md":
			f.md, err = next()
		case "--json":
			f.json, err = next()
		default:
			return f, fmt.Errorf("unknown flag %q", a)
		}
		if err != nil {
			return f, err
		}
	}
	return f, nil
}

func runReport(args []string) error {
	f, err := parse(args)
	if err != nil {
		return err
	}
	if f.labels == "" {
		return fmt.Errorf("report requires --labels")
	}
	labels, err := loadLabels(f.labels)
	if err != nil {
		return err
	}
	labels = filterRules(labels, f.rules)
	stats := precision.Compute(labels)
	return emit(stats, f)
}

func runScan(args []string) error {
	f, err := parse(args)
	if err != nil {
		return err
	}
	if f.dir == "" || f.labels == "" {
		return fmt.Errorf("scan requires --dir and --labels")
	}
	labels, err := loadLabels(f.labels)
	if err != nil {
		return err
	}
	scan, err := prgate.ScanDir(f.dir)
	if err != nil {
		return err
	}
	found := make([]precision.Found, 0, len(scan.Findings))
	for _, fn := range scan.Findings {
		found = append(found, precision.Found{
			RuleID:      fn.RuleID,
			Path:        fn.Path,
			Line:        fn.Line,
			Fingerprint: fn.Fingerprint,
		})
	}
	matched, unlabeled := precision.Resolve(found, labels)
	matched = filterRules(matched, f.rules)
	stats := precision.Compute(matched)
	if err := emit(stats, f); err != nil {
		return err
	}
	queued := 0
	for _, u := range unlabeled {
		if f.rules == "" || ruleSelected(u.RuleID, f.rules) {
			queued++
		}
	}
	fmt.Fprintf(os.Stderr, "\nscanned %d findings; %d labeled, %d unlabeled (labeling queue)\n",
		len(found), len(matched), queued)
	return nil
}

func loadLabels(path string) ([]precision.Label, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = fh.Close() }()
	return precision.LoadLabels(fh)
}

func filterRules(labels []precision.Label, rules string) []precision.Label {
	if rules == "" {
		return labels
	}
	var out []precision.Label
	for _, l := range labels {
		if ruleSelected(l.RuleID, rules) {
			out = append(out, l)
		}
	}
	return out
}

func ruleSelected(id, rules string) bool {
	for _, r := range strings.Split(rules, ",") {
		if strings.EqualFold(strings.TrimSpace(r), id) {
			return true
		}
	}
	return false
}

func emit(stats []precision.RuleStats, f flags) error {
	md := precision.Markdown(stats)
	if f.md != "" {
		if err := os.WriteFile(f.md, []byte(md), 0o644); err != nil {
			return err
		}
	} else {
		fmt.Print(md)
	}
	if f.json != "" {
		j, err := precision.JSON(stats)
		if err != nil {
			return err
		}
		if err := os.WriteFile(f.json, j, 0o644); err != nil {
			return err
		}
	}
	return nil
}
