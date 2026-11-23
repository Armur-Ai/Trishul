package cmd

import (
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/Armur-Ai/Trishul/internal/prgate"
	"github.com/Armur-Ai/Trishul/internal/verify"
)

var (
	verifyRepo   string
	verifyCommit string
	verifyRef    string
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Emit a Trishul Verified claim for this repo (attest it in your CI)",
	Long: `Scans the repo and prints a code-free "Trishul Verified" claim (repo, commit,
rule/tool version, grade, pass/fail). Your CI attaches it as a GitHub artifact
attestation; anyone then verifies it with 'gh attestation verify' — Trishul never
re-scans and hosts nothing. Local-first.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, _ := os.Getwd()
		return runVerify(dir, verifyRepo, verifyCommit, verifyRef, os.Stdout)
	},
}

// runVerify scans dir and prints the verification claim JSON.
func runVerify(dir, repo, commit, ref string, w io.Writer) error {
	scan, err := prgate.ScanDir(dir)
	if err != nil {
		return err
	}
	fs := scan.Findings
	grade := prgate.Grade(fs)
	passed := prgate.Grade(fs) != "F" // simple default; the Action uses the gate policy

	claim := verify.NewClaim(verify.Claim{
		Repo:         firstNonEmptyStr(repo, os.Getenv("GITHUB_REPOSITORY")),
		CommitSHA:    firstNonEmptyStr(commit, os.Getenv("GITHUB_SHA")),
		Ref:          firstNonEmptyStr(ref, os.Getenv("GITHUB_REF")),
		RulesVersion: "embedded",
		ToolVersion:  Version,
		Grade:        grade,
		Passed:       passed,
		NewFindings:  len(fs),
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
	})
	b, err := claim.Canonical()
	if err != nil {
		return err
	}
	var pretty map[string]any
	_ = json.Unmarshal(b, &pretty)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(pretty)
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func init() {
	verifyCmd.Flags().StringVar(&verifyRepo, "repo", "", "owner/name (defaults to $GITHUB_REPOSITORY)")
	verifyCmd.Flags().StringVar(&verifyCommit, "commit", "", "commit SHA (defaults to $GITHUB_SHA)")
	verifyCmd.Flags().StringVar(&verifyRef, "ref", "", "git ref (defaults to $GITHUB_REF)")
	rootCmd.AddCommand(verifyCmd)
}
