# FIREBASE-003: Cloud Storage rule grants an unconditional allow

A Storage match allows write/all paths with no condition.

## Metadata

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Confidence | 0.80 |
| Maturity | stable |
| Mode | comment |
| Languages | firebase-rules |
| File kinds | config |
| CWE | CWE-668 |
| OWASP | A01 |

## Description

A Cloud Storage `match` grants an unconditional allow (no condition or `if true`) on a
write or on an `{allPaths=**}` block, so stored objects are world-writable/readable with
no authorization.

## Fix

Require authentication and ownership before writing, and never leave a match /{allPaths=**} block with an unconditional allow.

## Examples

Bad:

```bad
match /{allPaths=**} { allow write: if true; }
```

Good:

```good
match /users/{userId}/{file} { allow write: if request.auth != null && request.auth.uid == userId; }
```

