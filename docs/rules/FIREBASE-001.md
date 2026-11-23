# FIREBASE-001: Firestore rule allows world read and write

A Firestore match grants allow read, write with an always-true condition.

## Metadata

| Field | Value |
| --- | --- |
| Severity | CRITICAL |
| Confidence | 0.80 |
| Maturity | stable |
| Mode | block |
| Languages | firebase-rules |
| File kinds | config |
| CWE | CWE-284 |
| OWASP | A01 |

## Description

A Firestore `match` grants `allow read, write` with no condition or an always-true
condition (`if true`), so the data is world-readable and world-writable by any client,
authenticated or not.

## Fix

Gate the rule behind an ownership/auth predicate (e.g. if request.auth != null && request.auth.uid == resource.data.ownerId); never ship allow read, write: if true.

## Examples

Bad:

```bad
match /notes/{id} { allow read, write: if true; }
```

Good:

```good
match /notes/{id} { allow read, write: if request.auth != null && request.auth.uid == resource.data.ownerId; }
```

