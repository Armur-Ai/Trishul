# CLIENT-SECRET-001: Secret assigned to a client-exposed environment variable

A secret-shaped value is bound to a NEXT_PUBLIC_/VITE_/… env var.

## Metadata

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Confidence | 0.70 |
| Maturity | stable |
| Mode | comment |
| Languages | javascript, typescript, env |
| File kinds | config, source |
| CWE | CWE-200 |
| OWASP | A02 |

## Description

A secret-shaped value (length + charset + entropy heuristic) is assigned to a
client-exposed environment variable (NEXT_PUBLIC_, EXPO_PUBLIC_, REACT_APP_, VITE_,
PUBLIC_). Variables with these prefixes are inlined into the client/browser bundle at
build time and are publicly readable.

## Fix

Remove the client-exposed prefix and keep the secret server-side; expose only non-sensitive values via a public prefix.

## Examples

Bad:

```bad
NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_51H8xQ2abcdef0123456789
```

Good:

```good
STRIPE_SECRET_KEY=sk_live_51H8xQ2abcdef0123456789
```

