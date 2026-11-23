# VIBE-ABUSE-003: Unvalidated req.body spread into a database write

A handler spreads raw req.body into a DB create/update, no validation.

## Metadata

| Field | Value |
| --- | --- |
| Severity | LOW |
| Confidence | 0.40 |
| Maturity | stable |
| Mode | comment |
| Languages | javascript, typescript, python |
| File kinds | source |
| CWE | CWE-20 |
| OWASP | A04 |

## Description

A mutating handler spreads `req.body` straight into a database create/update with no
schema validation in the file, so attackers can set arbitrary/unexpected fields
(mass assignment).

## Fix

Validate and whitelist the request body with a schema (zod/joi/yup for Node, pydantic for Python) before persisting; never spread raw `req.body` into a DB write.

## Examples

Bad:

```bad
await User.create({ ...req.body })
```

Good:

```good
const data = userSchema.parse(req.body); await User.create(data)
```

