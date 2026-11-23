# VIBE-AUTHZ-002: IDOR: record looked up by request id without owner scoping

A handler fetches by a request-supplied id with no owner predicate.

## Metadata

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Confidence | 0.50 |
| Maturity | stable |
| Mode | comment |
| Languages | javascript, typescript, python |
| File kinds | source |
| CWE | CWE-639 |
| OWASP | A01 |

## Description

A handler reads an id from the request (path/body/query) and queries by it with no
owner/user/tenant predicate, so a caller may access another user's record by changing the
id (IDOR). Independent of auth — an authenticated handler without owner scoping still qualifies.

## Fix

Scope the query to the authenticated principal with an ownership predicate (e.g. where { id, userId: session.user.id }) so callers cannot access records they do not own.

## Examples

Bad:

```bad
const doc = await prisma.note.findUnique({ where: { id: params.id } })
```

Good:

```good
const doc = await prisma.note.findUnique({ where: { id: params.id, userId: session.user.id } })
```

