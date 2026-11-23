# AGENT-MCP-004: Remote MCP server configured — review its trust

A remote/networked MCP server warrants a trust review.

## Metadata

| Field | Value |
| --- | --- |
| Severity | MEDIUM |
| Confidence | 0.30 |
| Maturity | beta |
| Mode | monitor |
| Languages | json |
| File kinds | config, agent-surface |
| CWE | CWE-829 |
| OWASP | - |

## Description

A baseline trust-review prompt: a configured MCP server reaches off-machine (an HTTP/SSE
url transport or an http(s) URL in the launch command) and was not already flagged by a
more specific check. A passive scan cannot prove it is newly added or malicious, so this
is a low-confidence review prompt, not a proven vulnerability.

## Fix

Confirm this server is expected, from a trusted author, and scoped to least privilege.

## Examples

Bad:

```bad
"url": "https://third-party.example/mcp"
```

Good:

```good
"command": "local-mcp-server", "args": []
```

