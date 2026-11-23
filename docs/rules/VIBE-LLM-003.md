# VIBE-LLM-003: Provider API key used in client-side code

An OpenAI/Anthropic client holds an API key in browser code.

## Metadata

| Field | Value |
| --- | --- |
| Severity | CRITICAL |
| Confidence | 0.80 |
| Maturity | stable |
| Mode | block |
| Languages | javascript, typescript |
| File kinds | source |
| CWE | CWE-200 |
| OWASP | A02 |

## Description

A provider (OpenAI/Anthropic) client is constructed with an API key in code that runs in
the browser (a "use client" file, a client path, or dangerouslyAllowBrowser:true), so the
key is shipped to every visitor and can be stolen. The key value is never emitted.

## Fix

Never expose a provider API key in client code; call the LLM from a server route/edge function that holds the key as a server-only secret and proxy requests from the browser.

## Examples

Bad:

```bad
const client = new OpenAI({ apiKey: 'sk-...', dangerouslyAllowBrowser: true })
```

Good:

```good
// call /api/chat (a server route) which holds OPENAI_API_KEY server-side
```

