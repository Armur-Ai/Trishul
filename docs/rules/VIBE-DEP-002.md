# VIBE-DEP-002: Unpinned dependency with no lockfile

A dependency floats and the project has no lockfile.

## Metadata

| Field | Value |
| --- | --- |
| Severity | LOW |
| Confidence | 0.50 |
| Maturity | stable |
| Mode | comment |
| Languages | json |
| File kinds | config |
| CWE | CWE-1357 |
| OWASP | A08 |

## Description

A registry-sourced dependency uses an unpinned/floating version spec (*, latest, x, or a
non-exact range) while the project has no lockfile anywhere, so installs are not
reproducible and can silently pull new code. Suppressed entirely when a lockfile is present.

## Fix

Pin to an exact registry version and/or commit a lockfile (package-lock.json / yarn.lock / pnpm-lock.yaml) to freeze the dependency tree.

## Examples

Bad:

```bad
"react": "*"
```

Good:

```good
"react": "18.3.1"
```

