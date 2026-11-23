# VIBE-PLACEHOLDER-004: Wildcard CORS origin combined with credentials

CORS allows origin '*' together with credentials.

## Metadata

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Confidence | 0.70 |
| Maturity | stable |
| Mode | comment |
| Languages | javascript, typescript, python, go |
| File kinds | source, config |
| CWE | CWE-942 |
| OWASP | A05 |

## Description

A wildcard CORS origin (`*`) is combined with credentials enabled in the same file,
allowing any site to make authenticated cross-origin requests to the application.

## Fix

Replace the `*` origin with an explicit allow-list of trusted origins when credentials are enabled.

## Examples

Bad:

```bad
app.use(cors({ origin: '*', credentials: true }))
```

Good:

```good
app.use(cors({ origin: ['https://app.example.com'], credentials: true }))
```

