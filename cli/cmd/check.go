package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Armur-Ai/Trishul/internal/precheck"
)

var (
	checkPath string
	checkName string
)

// popularServers is a small built-in list of well-known MCP server / package
// names for typosquat distance. (A fuller list ships via the daily bundle.)
var popularServers = []string{
	"@modelcontextprotocol/server-filesystem",
	"@modelcontextprotocol/server-github",
	"@modelcontextprotocol/server-postgres",
	"@modelcontextprotocol/server-memory",
	"@modelcontextprotocol/server-puppeteer",
	"@modelcontextprotocol/server-slack",
	"server-filesystem", "server-github", "server-postgres",
	"playwright-mcp", "context7", "sequential-thinking",
}

var checkCmd = &cobra.Command{
	Use:   "check [name]",
	Short: "Vet a package / MCP server / plugin before installing it (local)",
	Long: `Assesses something before you install it: typosquat distance to popular
names, risky install scripts (pre/post/install) and poisoned MCP tool
descriptions — returning a safe / caution / risky verdict with scripting exit
codes (0/1/2).

  trishul check server-fileystem           # name-only typosquat check
  trishul check --path ./downloaded-pkg    # inspect an already-fetched package dir
  trishul check some-server --path ./pkg   # both

Network fetch of a remote package is intentionally not built in yet (it needs a
hermetic sandbox); point --path at content you fetched with --ignore-scripts.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		name := checkName
		if name == "" && len(args) > 0 {
			name = args[0]
		}
		code, err := runCheck(name, checkPath, os.Stdout)
		if err != nil {
			return err
		}
		os.Exit(code)
		return nil
	},
}

// runCheck is the testable core.
func runCheck(name, path string, w io.Writer) (int, error) {
	var packageJSON []byte
	var toolDescriptions []string
	if path != "" {
		if b, err := os.ReadFile(filepath.Join(path, "package.json")); err == nil {
			packageJSON = b
		}
		toolDescriptions = readToolDescriptions(path)
		if name == "" {
			name = filepath.Base(path)
		}
	}

	rep := precheck.Assess(name, popularServers, packageJSON, toolDescriptions)

	fmt.Fprintf(w, "%s — verdict: %s\n", rep.Name, rep.Verdict)
	for _, r := range rep.Reasons {
		fmt.Fprintf(w, "  [%s] %s\n", r.Severity, r.Detail)
	}
	if len(rep.Reasons) == 0 {
		fmt.Fprintln(w, "  no risk signals found")
	}
	return rep.Verdict.ExitCode(), nil
}

// readToolDescriptions pulls MCP tool `description` fields from a package's
// mcp.json / server manifest if present (for the tool-poisoning check).
func readToolDescriptions(path string) []string {
	var out []string
	for _, cand := range []string{"mcp.json", ".mcp.json", "server.json"} {
		b, err := os.ReadFile(filepath.Join(path, cand))
		if err != nil {
			continue
		}
		var raw struct {
			Tools []struct {
				Description string `json:"description"`
			} `json:"tools"`
		}
		if json.Unmarshal(b, &raw) == nil {
			for _, t := range raw.Tools {
				if t.Description != "" {
					out = append(out, t.Description)
				}
			}
		}
	}
	return out
}

func init() {
	checkCmd.Flags().StringVar(&checkPath, "path", "", "inspect an already-fetched package directory")
	checkCmd.Flags().StringVar(&checkName, "name", "", "the name to check (alternative to the positional arg)")
	rootCmd.AddCommand(checkCmd)
}
