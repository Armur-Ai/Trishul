# SUPABASE-RLS-004: SECURITY DEFINER function without a pinned search_path

A SECURITY DEFINER function does not pin SET search_path.

## Metadata

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Confidence | 0.90 |
| Maturity | stable |
| Mode | comment |
| Languages | sql |
| File kinds | migration |
| CWE | CWE-284 |
| OWASP | A01 |

## Description

A `SECURITY DEFINER` function does not pin `SET search_path`; a mutable search_path can let
a caller hijack name resolution and run code with the definer's elevated privileges.

## Fix

Pin the search_path on SECURITY DEFINER functions, e.g. SET search_path = public, pg_temp.

## Examples

Bad:

```bad
create function f() returns void security definer as $$ ... $$ language sql;
```

Good:

```good
create function f() returns void security definer set search_path = public, pg_temp as $$ ... $$ language sql;
```

