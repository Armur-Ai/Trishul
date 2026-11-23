# VIBE-PLACEHOLDER-005: Debug mode enabled

Debug mode is turned on in configuration.

## Metadata

| Field | Value |
| --- | --- |
| Severity | MEDIUM |
| Confidence | 0.60 |
| Maturity | stable |
| Mode | comment |
| Languages | javascript, typescript, python, go, json, yaml |
| File kinds | source, config |
| CWE | CWE-489 |
| OWASP | A05 |

## Description

Debug mode is enabled (DEBUG=true, app.debug=true, FLASK_DEBUG=1, or NODE_ENV set to a
non-production value alongside debug config), which leaks stack traces and internals and
should never be on in production.

## Fix

Disable debug mode in production builds and drive it from an environment-specific configuration that defaults to off.

## Examples

Bad:

```bad
app.debug = True
```

Good:

```good
app.debug = False
```

