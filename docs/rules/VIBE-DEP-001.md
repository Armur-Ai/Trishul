# VIBE-DEP-001: Dependency sourced from a non-registry location

A package.json dependency points at a git/URL/file source.

## Metadata

| Field | Value |
| --- | --- |
| Severity | MEDIUM |
| Confidence | 0.50 |
| Maturity | stable |
| Mode | comment |
| Languages | json |
| File kinds | config |
| CWE | CWE-1104 |
| OWASP | A08 |

## Description

A package.json dependency is sourced from a non-registry location (git/git+/http(s)/
github:/gitlab:/file:/link:/raw URL), bypassing npm registry integrity checks. `npm:`
aliases and `workspace:`/`portal:` protocols are not flagged.

## Fix

Pin the dependency to a published registry version (or an npm: alias), or vendor-review the git/URL source and lock it to an immutable commit SHA.

## Examples

Bad:

```bad
"left-pad": "git+https://github.com/attacker/left-pad.git"
```

Good:

```good
"left-pad": "1.3.0"
```

