# SUPABASE-RLS-001: Table created without row-level security

A public table is created with no ENABLE ROW LEVEL SECURITY anywhere.

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

A public-schema table is created but no `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`
appears for it in any scanned migration, so the data layer is open to any client using the
anon/public API key. RLS enabled in a later migration suppresses the finding.

## Fix

Enable row-level security on the table (ALTER TABLE <t> ENABLE ROW LEVEL SECURITY) and add explicit policies.

## Examples

Bad:

```bad
create table public.notes (id uuid primary key, body text);
```

Good:

```good
create table public.notes (id uuid primary key, body text);
alter table public.notes enable row level security;
```

