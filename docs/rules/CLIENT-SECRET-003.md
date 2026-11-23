# CLIENT-SECRET-003: Privileged secret in a client-side file

A service_role JWT, sk-key, or private key appears in client code.

## Metadata

| Field | Value |
| --- | --- |
| Severity | CRITICAL |
| Confidence | 0.85 |
| Maturity | stable |
| Mode | block |
| Languages | javascript, typescript |
| File kinds | source |
| CWE | CWE-798, CWE-312 |
| OWASP | A02 |

## Description

A high-confidence privileged secret — a Supabase service_role JWT, an sk-style provider
key (OpenAI/Anthropic), or a PEM private key — appears in a file that looks client-side
(a client path or a "use client" directive). These must never ship to the browser.

## Fix

Keep privileged secrets server-side; call privileged APIs from a server route and rotate any key that reached client code.

## Examples

Bad:

```bad
"use client"; const sb = createClient(url, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.sig")
```

Good:

```good
"use client"; const sb = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY)
```

