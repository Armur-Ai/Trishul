# AGENT-MCP-001: MCP server launched via unpinned package runner

An MCP server auto-installs a floating package version each launch.

## Metadata

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Confidence | 0.90 |
| Maturity | stable |
| Mode | block |
| Languages | json |
| File kinds | config, agent-surface |
| CWE | CWE-829 |
| OWASP | A08 |

## Description

An MCP server is launched with an auto-installing package runner (npx -y/--yes, uvx,
bunx, pnpx) at a floating (unpinned) version, so the vetted code is not guaranteed to
be what runs on the developer's machine at each launch.

## Fix

Pin the MCP server package to an exact version (e.g. pkg@1.2.3) and verify its integrity.

## Examples

Bad:

```bad
"command": "npx", "args": ["-y", "some-mcp-server"]
```

Good:

```good
"command": "npx", "args": ["-y", "some-mcp-server@1.2.3"]
```

