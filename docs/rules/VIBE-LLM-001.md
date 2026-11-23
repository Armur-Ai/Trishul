# VIBE-LLM-001: Untrusted input interpolated into an LLM prompt (prompt injection)

Request-derived input is concatenated into an LLM prompt/message.

## Metadata

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Confidence | 0.60 |
| Maturity | stable |
| Mode | comment |
| Languages | javascript, typescript, python |
| File kinds | source |
| CWE | CWE-94 |
| OWASP | A03 |

## Description

Request-derived (untrusted) input is concatenated or interpolated directly into an LLM
prompt/message content via a dynamic string build, so an attacker can inject instructions
into the model (prompt injection). HIGH when the request source is direct, MEDIUM otherwise.

## Fix

Keep untrusted text in a separate, clearly delimited user-role message, validate/escape it, and constrain the model with a fixed, trusted system prompt instead of concatenating user input.

## Examples

Bad:

```bad
const prompt = `Answer this question: ${req.body.question}`
```

Good:

```good
messages: [{ role: 'system', content: SYSTEM }, { role: 'user', content: req.body.question }]
```

