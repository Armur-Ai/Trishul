# FIREBASE-004: Broad {document=**} catch-all with a permissive allow

A {document=**} catch-all grants a permissive unconditional allow.

## Metadata

| Field | Value |
| --- | --- |
| Severity | MEDIUM |
| Confidence | 0.80 |
| Maturity | stable |
| Mode | comment |
| Languages | firebase-rules |
| File kinds | config |
| CWE | CWE-732 |
| OWASP | A01 |

## Description

A Firestore `match` is a broad `{document=**}` catch-all with a permissive, unconditional
allow; it overrides more specific rules and exposes the whole database.

## Fix

Remove the catch-all allow or scope it behind auth/ownership, and grant access per-collection with explicit ownership predicates.

## Examples

Bad:

```bad
match /{document=**} { allow read, write: if true; }
```

Good:

```good
match /notes/{id} { allow read, write: if request.auth != null && request.auth.uid == resource.data.ownerId; }
```

