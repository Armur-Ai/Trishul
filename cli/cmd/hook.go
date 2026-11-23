package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/Armur-Ai/Trishul/internal/agenthook"
)

var hookCmd = &cobra.Command{
	Use:   "hook",
	Short: "Real-time guards for AI coding agents",
	Long: `Guards that run while an AI coding agent works, invoked by the agent's own
hook system. Each subcommand reads a single hook event on stdin and signals the
agent through its exit code.`,
}

var hookClaudeCodeCmd = &cobra.Command{
	Use:   "claude-code",
	Short: "Claude Code hook: guard an agent's edits and commands in real time",
	Long: `Reads one Claude Code hook event from stdin and guards the agent in real time.

It inspects each edit the moment it lands (PostToolUse on Write/Edit/MultiEdit/
NotebookEdit), scanning only the touched file and reporting only the issues the
edit introduced; it flags dangerous shell commands before they run (PreToolUse
on Bash); and it prints a summary when the session stops. A new high/critical
issue exits with code 2 and a concise explanation on stderr that the agent
reads; everything else exits 0. The scan is hermetic — files are only read,
never executed, and nothing leaves the machine.

Configure via .trishul.yml at the repo root:

  agent_hook:
    block_on: high          # info|low|medium|high|critical
    rules_exclude: []        # rule IDs the hook never reports
    bash_guard: warn         # warn|block|off

Register it with Claude Code (~/.claude/settings.json):

  {
    "hooks": {
      "PostToolUse": [{ "matcher": "Write|Edit|MultiEdit|NotebookEdit",
        "hooks": [{ "type": "command", "command": "trishul hook claude-code" }] }],
      "PreToolUse":  [{ "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "trishul hook claude-code" }] }],
      "Stop":        [{ "hooks": [{ "type": "command", "command": "trishul hook claude-code" }] }]
    }
  }`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(agenthook.Run(os.Stdin, os.Stdout, os.Stderr, agenthook.Options{}))
	},
}

func init() {
	rootCmd.AddCommand(hookCmd)
	hookCmd.AddCommand(hookClaudeCodeCmd)
}
