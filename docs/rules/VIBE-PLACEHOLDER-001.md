# VIBE-PLACEHOLDER-001: Hardcoded placeholder or weak signing secret

A signing/session secret is assigned a weak or placeholder value.

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
| OWASP | A05 |

## Description

A signing/session/JWT secret is hardcoded to a weak or placeholder value (a known
placeholder word, or a very short string) rather than read from the environment or a
secrets manager. Lines that reference env access are suppressed; the value is reported redacted.

## Fix

Generate a strong random value and inject it via an environment variable or secrets manager; never commit credentials to source control.

## Examples

Bad:

```bad
const JWT_SECRET = "changeme"
```

Good:

```good
const JWT_SECRET = process.env.JWT_SECRET
```

