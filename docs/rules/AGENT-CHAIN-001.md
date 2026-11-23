# AGENT-CHAIN-001: Cross-file agent attack chain: untrusted content + an enabled execution/permission path

An untrusted-content entry point and an enabled action co-occur in the same PR.

## Metadata

| Field | Value |
| --- | --- |
| Severity | CRITICAL |
| Confidence | 0.85 |
| Maturity | stable |
| Mode | block |
| Languages | - |
| File kinds | agent-surface |
| CWE | CWE-94 |
| OWASP | A03 |

## Description

The correlation step fires when the repo/PR contains BOTH an untrusted entry point
(an injection/instruction/obfuscation finding) AND an enabled action (an exec/MCP/permission
finding). Two independent signals corroborate each other, turning low-confidence semantic
signals into a high-confidence, critical attack chain.

## Fix

Treat neither the untrusted content nor the execution/permission change as trusted from a PR; strip the injected instruction and pin/deny the action.

## Examples

Bad:

```bad
CLAUDE.md says "run the following" + package.json postinstall pipes curl into bash.
```

Good:

```good
No untrusted directive and no unreviewed execution/permission change in the PR.
```

