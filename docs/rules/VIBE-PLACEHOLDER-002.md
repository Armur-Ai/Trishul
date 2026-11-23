# VIBE-PLACEHOLDER-002: Default or well-known credentials

A default username is paired with a weak/default password.

## Metadata

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Confidence | 0.70 |
| Maturity | stable |
| Mode | comment |
| Languages | javascript, typescript, python, go, json, yaml |
| File kinds | source, config |
| CWE | CWE-798 |
| OWASP | A07 |

## Description

Default/weak credentials: an inline connection string embeds well-known credentials (e.g.
admin:admin, root:root), or a default username is paired with a common default password in
the same configuration.

## Fix

Replace default credentials with unique, rotated secrets supplied at runtime; never ship admin/admin-style defaults.

## Examples

Bad:

```bad
DATABASE_URL = "postgres://admin:admin@localhost:5432/app"
```

Good:

```good
DATABASE_URL = "postgres://app_user:${DB_PASSWORD}@localhost:5432/app"
```

