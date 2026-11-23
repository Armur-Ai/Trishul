package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// `trishul init claude` — the one-command install of the real-time agent guard
// (plan D1). It merges Trishul's hooks into the user's Claude Code settings so
// every edit the agent makes is scanned in-turn and dangerous shell commands are
// flagged before they run. Idempotent, with a .bak backup. Fully local.

const hookCommand = "trishul hook claude-code"

var initClaudeCmd = &cobra.Command{
	Use:   "claude",
	Short: "Install the Trishul guard into Claude Code (real-time scan of agent edits)",
	Long: `Adds Trishul's hooks to your Claude Code settings so every file the agent
writes is scanned the moment it lands (new high/critical issues are fed back so
the agent fixes them in the same turn), and dangerous shell commands are flagged
before they run. Idempotent; writes a .bak backup. Everything runs locally —
your code never leaves your machine.

  trishul init claude            # user settings (~/.claude/settings.json)
  trishul init claude --project  # project settings (.claude/settings.json)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		project, _ := cmd.Flags().GetBool("project")
		home, _ := os.UserHomeDir()
		path := filepath.Join(home, ".claude", "settings.json")
		if project {
			path = filepath.Join(".claude", "settings.json")
		}
		action, err := installClaudeHooks(path)
		if err != nil {
			return err
		}
		fmt.Println(color.GreenString("%s %s", action, path))
		fmt.Println("Trishul now guards this agent. Try it: ask your agent to write code with a hardcoded secret.")
		return nil
	},
}

// claudeHookEvents maps each Claude Code hook event to the tool matcher Trishul
// registers for. An empty matcher means "all".
var claudeHookEvents = []struct {
	event, matcher string
}{
	{"PostToolUse", "Write|Edit|MultiEdit|NotebookEdit"},
	{"PreToolUse", "Bash"},
	{"Stop", ""},
}

// installClaudeHooks idempotently merges Trishul's hook entries into the settings
// file, preserving any existing hooks. Returns "added"/"updated"/"unchanged".
func installClaudeHooks(path string) (string, error) {
	root, err := readJSONObject(path)
	if err != nil {
		return "", err
	}
	hooks, _ := root["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	changed := false
	for _, e := range claudeHookEvents {
		list, _ := hooks[e.event].([]any)
		if hookPresent(list) {
			continue
		}
		entry := map[string]any{
			"hooks": []any{map[string]any{"type": "command", "command": hookCommand}},
		}
		if e.matcher != "" {
			entry["matcher"] = e.matcher
		}
		hooks[e.event] = append(list, entry)
		changed = true
	}
	if !changed {
		return "unchanged", nil
	}
	root["hooks"] = hooks
	if err := writeJSONObject(path, root); err != nil {
		return "", err
	}
	return "installed", nil
}

// hookPresent reports whether any entry in a hook-event list already runs the
// Trishul hook command (so re-running is idempotent).
func hookPresent(list []any) bool {
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		inner, _ := m["hooks"].([]any)
		for _, h := range inner {
			hm, ok := h.(map[string]any)
			if ok && hm["command"] == hookCommand {
				return true
			}
		}
	}
	return false
}

func init() {
	initClaudeCmd.Flags().Bool("project", false, "write project settings (.claude/settings.json) instead of user settings")
	initCmd.AddCommand(initClaudeCmd)
}
