# VIBE-PLACEHOLDER-006: Security-related TODO/FIXME marker

A comment marks an unfinished or bypassed security control.

## Metadata

| Field | Value |
| --- | --- |
| Severity | LOW |
| Confidence | 0.40 |
| Maturity | stable |
| Mode | monitor |
| Languages | javascript, typescript, python, go |
| File kinds | source |
| CWE | CWE-1111 |
| OWASP | - |

## Description

A security-related TODO/FIXME/HACK/XXX marker inside a comment indicates an unfinished or
intentionally bypassed security control (auth, validation, verification). Informational and
potentially noisy, so it is reported at LOW severity.

## Fix

Resolve the outstanding security work before shipping, or track it as a blocking issue; do not leave auth/validation gaps behind a comment.

## Examples

Bad:

```bad
// TODO: add the auth check here before launch
```

Good:

```good
// Auth is enforced by requireUser() middleware above.
```

