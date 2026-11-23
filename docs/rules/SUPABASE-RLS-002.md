# SUPABASE-RLS-002: RLS policy with an always-true predicate (effectively public)

A policy uses USING (true) or WITH CHECK (true).

## Metadata

| Field | Value |
| --- | --- |
| Severity | CRITICAL |
| Confidence | 0.90 |
| Maturity | stable |
| Mode | block |
| Languages | sql |
| File kinds | migration |
| CWE | CWE-862 |
| OWASP | A01 |

## Description

An RLS policy uses `USING (true)` (matches every row for every caller) or `WITH CHECK (true)`
(lets any caller write arbitrary rows), making the table effectively public despite RLS
being enabled.

## Fix

Replace the always-true predicate with an auth/ownership condition such as (auth.uid() = user_id).

## Examples

Bad:

```bad
create policy p on public.notes for select using (true);
```

Good:

```good
create policy p on public.notes for select using (auth.uid() = user_id);
```

