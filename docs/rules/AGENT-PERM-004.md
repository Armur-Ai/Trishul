# AGENT-PERM-004: Security check disabled

Agent config turns off an integrity/TLS verification step.

## Metadata

| Field | Value |
| --- | --- |
| Severity | MEDIUM |
| Confidence | 0.70 |
| Maturity | stable |
| Mode | comment |
| Languages | json, yaml, shell |
| File kinds | config, ci, agent-surface |
| CWE | CWE-732 |
| OWASP | A05 |

## Description

An agent config or environment turns off an integrity/security verification step: a
verify-signatures/ssl-verify/strict-ssl/checksum flag set false, or an env override such
as NODE_TLS_REJECT_UNAUTHORIZED=0, PYTHONHTTPSVERIFY=0, or GIT_SSL_NO_VERIFY=1.

## Fix

Re-enable signature/SSL/security verification; remove the verification-disabling override.

## Examples

Bad:

```bad
NODE_TLS_REJECT_UNAUTHORIZED=0
```

Good:

```good
NODE_TLS_REJECT_UNAUTHORIZED=1
```

