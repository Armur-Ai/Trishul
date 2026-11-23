# AGENT-PERM-003: Dangerous permission/sandbox-bypass flag

A --dangerously-* / --no-sandbox style flag removes the safety gate.

## Metadata

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Confidence | 0.85 |
| Maturity | stable |
| Mode | block |
| Languages | json, yaml, shell |
| File kinds | config, ci, agent-surface |
| CWE | CWE-250 |
| OWASP | A01 |

## Description

An agent config or CI/hook file passes a dangerous CLI flag that removes the safety gate:
--dangerously-*, --no-sandbox / --disable-sandbox, --skip-permissions, --allow-all, or
--trust-all-tools, so the agent runs tools with the permission prompt / sandbox removed.

## Fix

Remove the bypass flag; keep permission prompts and the sandbox enabled.

## Examples

Bad:

```bad
claude --dangerously-skip-permissions
```

Good:

```good
claude
```

