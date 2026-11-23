package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	trishul "github.com/Armur-Ai/Trishul"
	"github.com/Armur-Ai/Trishul/internal/agentrules"
	"github.com/Armur-Ai/Trishul/internal/rules"
)

var initRulesTools string

var initRulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Write secure-coding rules files for your AI tools (CLAUDE.md, Cursor, …)",
	Long: `Generates a stack-aware security checklist — derived from Trishul's rule
catalog — into the instruction files your AI coding tools read, so the agent
avoids the mistakes Trishul would otherwise flag.

It detects your stack (Next.js/Supabase/Firebase/Express/FastAPI/Django/Rails/Go)
and writes only the relevant rules, between <!-- trishul:begin/end --> markers so
re-running updates just that section. Fully local; nothing leaves your machine.

  trishul init rules                      # claude, cursor, agents
  trishul init rules --tools claude,copilot,windsurf,gemini`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cat, err := trishul.Catalog()
		if err != nil {
			return fmt.Errorf("load rule catalog: %w", err)
		}
		tools := parseTools(initRulesTools)
		return runInitRules(".", tools, cat, os.Stdout)
	},
}

// parseTools splits a comma list into agentrules.Tool values (defaulting to
// claude,cursor,agents when empty).
func parseTools(csv string) []agentrules.Tool {
	if strings.TrimSpace(csv) == "" {
		return []agentrules.Tool{agentrules.Claude, agentrules.Cursor, agentrules.Agents}
	}
	var out []agentrules.Tool
	for _, t := range strings.Split(csv, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, agentrules.Tool(t))
		}
	}
	return out
}

// runInitRules renders the rules section for each tool and idempotently upserts it
// into the tool's file under root. Testable (root + writer injected).
func runInitRules(root string, tools []agentrules.Tool, cat *rules.Catalog, w io.Writer) error {
	stacks := agentrules.Stacks(root)
	for _, tool := range tools {
		rel := agentrules.FileFor(tool)
		if rel == "" {
			fmt.Fprintf(w, "skip: unknown tool %q\n", tool)
			continue
		}
		p := filepath.Join(root, rel)
		existing := ""
		if b, err := os.ReadFile(p); err == nil {
			existing = string(b)
		}
		body := agentrules.Render(cat, stacks, tool)
		updated := agentrules.UpsertSection(existing, body)
		if updated == existing {
			fmt.Fprintf(w, "unchanged: %s\n", rel)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(updated), 0o644); err != nil {
			return err
		}
		action := "updated"
		if existing == "" {
			action = "created"
		}
		fmt.Fprintf(w, "%s: %s\n", action, rel)
	}
	if len(stacks) > 0 {
		fmt.Fprintf(w, "(detected stack: %s)\n", strings.Join(stacks, ", "))
	}
	return nil
}

func init() {
	initRulesCmd.Flags().StringVar(&initRulesTools, "tools", "", "comma list: claude,cursor,agents,copilot,windsurf,gemini (default: claude,cursor,agents)")
	initCmd.AddCommand(initRulesCmd)
}
