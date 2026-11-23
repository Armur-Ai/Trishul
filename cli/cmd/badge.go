package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Armur-Ai/Trishul/internal/badge"
	"github.com/Armur-Ai/Trishul/internal/prgate"
)

var badgeWrite string

var badgeCmd = &cobra.Command{
	Use:   "badge",
	Short: "Emit a shields.io badge JSON for this repo (committed to your repo, no server)",
	Long: `Scans the current repo and emits a shields.io endpoint JSON describing the
result. Commit it to your repo (e.g. .trishul/badge.json) and shields.io renders
the badge straight from your raw.githubusercontent.com — no Trishul server is
involved. The GitHub Action does this automatically; this command is for local
use and for printing the markdown snippet.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, _ := os.Getwd()
		return runBadge(dir, badgeWrite, os.Stdout)
	},
}

// runBadge scans dir, builds the badge endpoint, prints it (and the markdown),
// and optionally writes it to writePath.
func runBadge(dir, writePath string, w io.Writer) error {
	scan, err := prgate.ScanDir(dir)
	if err != nil {
		return err
	}
	ep := badge.ForGrade(prgate.Grade(scan.Findings))
	data, err := ep.JSON()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "%s\n", data)

	if writePath != "" {
		if err := os.MkdirAll(filepath.Dir(writePath), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(writePath, data, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(w, "wrote %s\n", writePath)
		fmt.Fprintf(w, "\nMarkdown (replace OWNER/REPO):\n[![Trishul](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/OWNER/REPO/main/%s)](https://github.com/OWNER/REPO/security/code-scanning)\n", writePath)
	}
	return nil
}

func init() {
	badgeCmd.Flags().StringVar(&badgeWrite, "write", "", "also write the badge JSON to this path (e.g. .trishul/badge.json)")
	rootCmd.AddCommand(badgeCmd)
}
