# FIREBASE-002: Firestore/Storage rule allows any authenticated user without ownership check

A rule allows access for request.auth != null with no ownership predicate.

## Metadata

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Confidence | 0.60 |
| Maturity | stable |
| Mode | comment |
| Languages | firebase-rules |
| File kinds | config |
| CWE | CWE-285 |
| OWASP | A01 |

## Description

A Firestore/Storage `match` allows read or write for any authenticated user
(`request.auth != null`) with no ownership check, so any signed-in user can access every
document in the collection.

## Fix

Scope the rule to the resource owner (e.g. if request.auth != null && request.auth.uid == resource.data.ownerId).

## Examples

Bad:

```bad
match /notes/{id} { allow read: if request.auth != null; }
```

Good:

```good
match /notes/{id} { allow read: if request.auth != null && request.auth.uid == resource.data.ownerId; }
```

