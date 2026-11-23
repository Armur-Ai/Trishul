---
description: Audit your AI / MCP setup — servers, tokens, permissions (local, offline)
allowed-tools: Bash(trishul:*)
---

Audit the MCP servers, tokens, and permissions configured across the AI clients
on this machine (Claude, Cursor, Windsurf, VS Code, Zed, Codex, Gemini).

!`trishul audit-mcp`

Review the audit above and report back:

- The grade and the most serious findings (unpinned servers, plaintext tokens,
  overbroad permissions, insecure remote servers, shadowed tool names, the
  "lethal trifecta").
- For each finding, the concrete fix Trishul recommends.

To audit a specific config or a repo's committed `.mcp.json`, re-run with a path:
`trishul audit-mcp --path <dir-or-file>`.

This runs entirely locally and offline — config files are only read, never
executed, and nothing leaves this machine.
