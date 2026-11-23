# Trishul advisories

An OSV-schema-subset feed of security advisories for AI-agent extensions, so
Trishul can flag a known-bad package/server offline. Each `*.json` file is an
array of advisories (see `internal/advisory`).

Ecosystems:
- `npm`, `PyPI` — standard OSV ecosystems.
- `MCP` — an MCP server, identified by its package/command name.
- `ClaudePlugin` — a Claude Code plugin, identified by its plugin name.

Advisory id convention: `TRISHUL-<ECOSYSTEM>-<YEAR>-<NNNN>`.

Publication of `armur.ai/trishul/advisories/all.json` is a D-HUMAN item; this
directory is the source snapshot bundled into the binary / refreshed on `--update`.
