# VIBE-PLACEHOLDER-003: Disabled TLS/certificate verification

Code disables TLS/certificate validation.

## Metadata

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Confidence | 0.80 |
| Maturity | stable |
| Mode | comment |
| Languages | javascript, typescript, python, go |
| File kinds | source, config |
| CWE | CWE-295 |
| OWASP | A05 |

## Description

TLS/certificate verification is disabled (verify=False, rejectUnauthorized:false,
NODE_TLS_REJECT_UNAUTHORIZED=0, or InsecureSkipVerify:true), exposing traffic to
man-in-the-middle attacks.

## Fix

Keep certificate/host verification enabled; fix the underlying trust issue (install the correct CA) instead of disabling validation.

## Examples

Bad:

```bad
requests.get(url, verify=False)
```

Good:

```good
requests.get(url, verify=True)
```

