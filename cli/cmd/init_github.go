package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// actionVersion is the Trishul Action release new workflows are pinned to.
// Bump on each release.
const actionVersion = "v0.2.0"

const workflowPath = ".github/workflows/trishul.yml"

func trishulWorkflow(failOn string) string {
	failLine := "          # fail-on: high        # uncomment to block merges on new high/critical issues\n"
	if failOn != "" {
		failLine = fmt.Sprintf("          fail-on: %s\n", failOn)
	}
	return `# Trishul PR security gate: reports only the security issues each PR introduces
# (AI agent supply-chain, Vibe Top 10, leaked secrets). Docs: https://github.com/Armur-Ai/Trishul
name: Trishul

on:
  pull_request:
  push:
    branches: [main, master]

permissions:
  contents: read
  pull-requests: write    # one PR comment, edited in place
  security-events: write  # SARIF -> code scanning

jobs:
  trishul:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Armur-Ai/Trishul@` + actionVersion + `
        with:
          min-severity: medium
` + failLine
}

var initGitHubCmd = &cobra.Command{
	Use:   "github",
	Short: "Add the Trishul PR security gate to this repo's GitHub Actions",
	Long: `Writes ` + workflowPath + ` so every pull request is checked for new
security issues. With --pr, commits it on a new branch, pushes, and opens a
pull request using the GitHub CLI (gh).

Prefer zero YAML? Install the Trishul GitHub App instead:
  https://armur.ai/trishul-app/`,
	Run: func(cmd *cobra.Command, args []string) {
		failOn, _ := cmd.Flags().GetString("fail-on")
		openPR, _ := cmd.Flags().GetBool("pr")
		force, _ := cmd.Flags().GetBool("force")

		root, err := gitOut("rev-parse", "--show-toplevel")
		if err != nil {
			color.Red("Not inside a git repository.")
			os.Exit(1)
		}
		target := filepath.Join(root, workflowPath)
		if _, err := os.Stat(target); err == nil && !force {
			color.Yellow("%s already exists (use --force to overwrite).", workflowPath)
			os.Exit(1)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			color.Red("%v", err)
			os.Exit(1)
		}
		if err := os.WriteFile(target, []byte(trishulWorkflow(failOn)), 0o644); err != nil {
			color.Red("%v", err)
			os.Exit(1)
		}
		color.Green("Wrote %s", workflowPath)

		if !openPR {
			fmt.Println("Commit it and open a PR. Trishul will comment only if a PR introduces an issue.")
			fmt.Println("Or run 'trishul init github --pr' to have it done for you.")
			return
		}
		if _, err := exec.LookPath("gh"); err != nil {
			color.Red("--pr needs the GitHub CLI (gh). Install it from https://cli.github.com")
			os.Exit(1)
		}
		branch := "trishul/setup"
		steps := [][]string{
			{"git", "-C", root, "checkout", "-b", branch},
			{"git", "-C", root, "add", workflowPath},
			{"git", "-C", root, "commit", "-m", "ci: add Trishul PR security gate"},
			{"git", "-C", root, "push", "-u", "origin", branch},
			{"gh", "pr", "create", "--head", branch, "--title", "ci: add Trishul PR security gate", "--body",
				"Adds the [Trishul](https://github.com/Armur-Ai/Trishul) PR security gate.\n\n" +
					"- Reports only issues a PR **introduces** (diffed against the merge base), so existing debt is not noise.\n" +
					"- Checks AI agent supply-chain risks (CLAUDE.md / .cursorrules / MCP configs), the Vibe Top 10, and leaked secrets.\n" +
					"- Non-blocking unless `fail-on` is set. One PR comment, edited in place, and only when there is something to say."},
		}
		for _, s := range steps {
			c := exec.Command(s[0], s[1:]...)
			c.Dir, c.Stdout, c.Stderr = root, os.Stdout, os.Stderr
			if err := c.Run(); err != nil {
				color.Red("'%s' failed: %v", strings.Join(s[:min(len(s), 4)], " "), err)
				os.Exit(1)
			}
		}
		color.Green("Opened a pull request adding Trishul.")
	},
}

func gitOut(args ...string) (string, error) {
	out, err := exec.Command("git", args...).Output()
	return strings.TrimSpace(string(out)), err
}

func init() {
	initGitHubCmd.Flags().String("fail-on", "", "block merges on new findings at or above this severity (critical|high|medium)")
	initGitHubCmd.Flags().Bool("pr", false, "commit on a new branch, push, and open a pull request with gh")
	initGitHubCmd.Flags().Bool("force", false, "overwrite an existing workflow")
	initCmd.AddCommand(initGitHubCmd)
}
