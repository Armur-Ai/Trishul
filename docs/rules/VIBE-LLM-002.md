# VIBE-LLM-002: LLM output flows into a dangerous sink

Model output reaches eval/exec/SQL/innerHTML.

## Metadata

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Confidence | 0.80 |
| Maturity | stable |
| Mode | block |
| Languages | javascript, typescript, python |
| File kinds | source |
| CWE | CWE-94, CWE-95 |
| OWASP | A03 |

## Description

An LLM response/completion value flows into a dangerous sink (eval/new Function,
exec/child_process/os.system/subprocess, a SQL query/execute/raw, or
dangerouslySetInnerHTML/innerHTML); model output is untrusted and can carry injected code.

## Fix

Treat model output as untrusted — do not eval/exec it or interpolate it into SQL or HTML; parse into a strict schema, use parameterized queries, and escape before any DOM insertion.

## Examples

Bad:

```bad
eval(completion.choices[0].message.content)
```

Good:

```good
const parsed = resultSchema.parse(JSON.parse(completion.choices[0].message.content))
```

