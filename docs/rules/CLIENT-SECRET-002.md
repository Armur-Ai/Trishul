# CLIENT-SECRET-002: Committed .env file contains a secret

A committed .env assigns a secret-shaped value to a key.

## Metadata

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Confidence | 0.70 |
| Maturity | stable |
| Mode | comment |
| Languages | env |
| File kinds | config |
| CWE | CWE-312 |
| OWASP | A02 |

## Description

A committed `.env` file (not an example/template) assigns a secret-shaped value to a key.
Secrets stored in committed env files are exposed to anyone with repository access; the
finding notes when the file does not appear to be gitignored.

## Fix

Remove the secret from the committed .env, add .env to .gitignore, rotate the value, and source it from a secrets manager.

## Examples

Bad:

```bad
DATABASE_URL=postgres://app:9f3c1ad2e7b84f0c9a12@db.example:5432/app
```

Good:

```good
# .env is gitignored; DATABASE_URL is injected at deploy time
```

