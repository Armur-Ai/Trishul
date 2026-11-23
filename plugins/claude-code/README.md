# Trishul — Claude Code plugin

Real-time, **local-first** security guardrails for Claude Code, powered by the
[Trishul](https://github.com/Armur-Ai/Trishul) scanner.

## What it does

Installing this plugin wires Trishul into your Claude Code session in three ways:

1. **Live edit & command guards (hooks).** Trishul runs as Claude works:
   - `PostToolUse` on `Write | Edit | MultiEdit | NotebookEdit` — scans each file
     the moment an edit lands and reports only the issues that edit introduced.
   - `PreToolUse` on `Bash` — flags dangerous shell commands before they run.
   - `Stop` / `SessionEnd` — prints a short session security tally.

   A new high/critical issue exits non-zero with a concise explanation the agent
   reads and acts on; everything else stays out of the way.

2. **MCP tools.** The plugin bundles Trishul's MCP server (`trishul mcp`), so the
   agent can invoke Trishul's scanning tools directly during a session.

3. **Slash commands:**
   - `/trishul:scan [path]` — scan the workspace (or a given path) on demand.
   - `/trishul:audit-mcp` — audit your MCP servers, tokens, and permissions.
   - `/trishul:fix <finding-id>` — generate a minimal patch for a finding.

## Prerequisites

The `trishul` binary must be on your `PATH`. The plugin's hooks, MCP server, and
commands all shell out to it.

```sh
# Build from source (Go 1.25+)
go install github.com/Armur-Ai/Trishul/cmd/trishul@latest
trishul --version
```

## Install

Once the marketplace repo exists (see below), add it and install:

```
/plugin marketplace add Armur-Ai/claude-plugins
/plugin install trishul@armur-claude-plugins
```

You can also point Claude Code at a local checkout of this directory during
development with `/plugin marketplace add <path-to-marketplace>`.

## Configure (optional)

Tune the live guards from a `.trishul.yml` at your repo root:

```yaml
agent_hook:
  block_on: high        # info | low | medium | high | critical
  rules_exclude: []     # rule IDs the hook never reports
  bash_guard: warn      # warn | block | off
```

## Local-first assurance

Everything this plugin does runs **on your machine**:

- The scanner only **reads** files — it never executes them.
- The MCP audit only reads AI-client config files.
- **Nothing leaves your machine.** No telemetry, no uploads, no network calls are
  required for the hooks, the MCP scanner, or the `scan` / `audit-mcp` commands.

The one exception is opt-in: `/trishul:fix` can call a hosted model
(`ANTHROPIC_API_KEY`) to draft a patch — or you can keep that local too by
pointing it at an Ollama instance. Fixes are applied locally either way.
