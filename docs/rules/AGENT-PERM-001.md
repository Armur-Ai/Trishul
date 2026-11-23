# AGENT-PERM-001: Blanket allow-all tool permissions

Agent config permits every tool without per-tool review.

## Metadata

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Confidence | 0.85 |
| Maturity | stable |
| Mode | block |
| Languages | json, yaml |
| File kinds | config, agent-surface |
| CWE | CWE-732 |
| OWASP | A01 |

## Description

An agent config grants a blanket allow-all tool permission: a wildcard `"*"`, an `"all"`
value, or a broad per-tool wildcard like `Bash(*)` in an allow/allowedTools/permissions
field (inline or in a multi-line array), so every tool runs without per-tool review.

## Fix

Replace the wildcard with an explicit least-privilege allow-list.

## Examples

Bad:

```bad
"allowedTools": ["*"]
```

Good:

```good
"allowedTools": ["Read", "Grep", "Bash(go test:*)"]
```

