# SUPABASE-RLS-003: RLS policy grants write/ALL to the anon role

A policy gives the anon role a write or ALL operation.

## Metadata

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Confidence | 0.90 |
| Maturity | stable |
| Mode | comment |
| Languages | sql |
| File kinds | migration |
| CWE | CWE-862 |
| OWASP | A01 |

## Description

An RLS policy grants a write or ALL operation (or a policy with no FOR clause, which
defaults to ALL) to the `anon` role, exposing the data layer to unauthenticated callers.

## Fix

Scope sensitive operations to the authenticated role and an ownership predicate; do not grant write/ALL to anon.

## Examples

Bad:

```bad
create policy p on public.notes for all to anon using (true);
```

Good:

```good
create policy p on public.notes for select to authenticated using (auth.uid() = user_id);
```

