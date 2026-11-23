# AGENT-PERM-002: Agent approval/confirmation disabled

Agent config disables approval or enables auto-approve/YOLO.

## Metadata

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Confidence | 0.85 |
| Maturity | stable |
| Mode | block |
| Languages | json, yaml |
| File kinds | config, agent-surface |
| CWE | CWE-250 |
| OWASP | A01 |

## Description

An agent config removes the human approval gate: a require-approval/confirmation flag set
false, an auto-approve/auto-run/skip-confirmation/YOLO flag set true, or a permission mode
of `bypassPermissions`/`yolo`, so tool calls run without per-action approval.

## Fix

Keep approval/confirmation required for tool execution; disable auto-approve / YOLO / bypass-permissions modes.

## Examples

Bad:

```bad
"autoApprove": true
```

Good:

```good
"requireApproval": true
```

