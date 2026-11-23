# AGENT-MCP-003: Secret embedded in MCP server config

A committed credential is embedded in MCP server config.

## Metadata

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Confidence | 0.70 |
| Maturity | stable |
| Mode | comment |
| Languages | json |
| File kinds | config, agent-surface |
| CWE | CWE-798 |
| OWASP | A05 |

## Description

An MCP server config embeds a literal credential (a recognizable key shape such as
sk-ant-/ghp_/AKIA/JWT, or a secret-named key with a literal value). The value is only
ever reported redacted; environment references and placeholders are ignored.

## Fix

Move the secret to an environment variable / secret store and rotate the exposed value.

## Examples

Bad:

```bad
"env": { "ANTHROPIC_API_KEY": "sk-ant-abcdef0123456789" }
```

Good:

```good
"env": { "ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}" }
```

