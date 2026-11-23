# SUPABASE-RLS-005: Public storage bucket

A storage bucket is created with public = true.

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

A Supabase storage bucket is created with `public = true`, so its objects are readable by
anyone without authorization.

## Fix

Create the bucket as private (public = false) and gate object access behind storage RLS policies.

## Examples

Bad:

```bad
insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
```

Good:

```good
insert into storage.buckets (id, name, public) values ('avatars', 'avatars', false);
```

