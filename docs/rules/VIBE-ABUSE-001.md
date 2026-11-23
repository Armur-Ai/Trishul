# VIBE-ABUSE-001: Auth or LLM endpoint without rate limiting

An auth/LLM endpoint is exposed with no rate limiter in the project.

## Metadata

| Field | Value |
| --- | --- |
| Severity | MEDIUM |
| Confidence | 0.50 |
| Maturity | stable |
| Mode | comment |
| Languages | javascript, typescript, python |
| File kinds | source |
| CWE | CWE-307, CWE-770 |
| OWASP | A04 |

## Description

An authentication endpoint (login/signup/password-reset/OTP) or an LLM-provider call is
exposed but no rate limiter is present anywhere in the project, so the surface can be
brute-forced or abused for cost/DoS. Suppressed when a rate limiter is detected anywhere.

## Fix

Add a rate limiter (express-rate-limit / @upstash/ratelimit for Node, slowapi for FastAPI/Flask) as middleware on this route, keyed by IP and/or account.

## Examples

Bad:

```bad
app.post('/login', loginHandler)
```

Good:

```good
app.post('/login', rateLimit({ windowMs: 60000, max: 10 }), loginHandler)
```

