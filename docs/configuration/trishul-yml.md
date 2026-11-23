# `.trishul.yml` — project configuration (v2)

Place `.trishul.yml` at your repository root. Trishul layers it over built-in
defaults; anything you omit keeps its default. A JSON Schema for editor
completion lives at [`schemas/trishul-yml.schema.json`](../../schemas/trishul-yml.schema.json).

> **Policy is read from the base branch.** The `gate` block that decides what
> blocks a PR is always taken from the target branch, so a pull request cannot
> weaken the gate on itself. Inline `trishul-ignore` suppressions may come from
> the PR head, but they are listed in the summary as "suppressed in this PR" so
> reviewers see them.

## Full example

```yaml
# Start from a named preset (default | strict | agent).
profile: default

# How much Trishul writes on a PR.
comments:
  max_inline: 10      # at most N inline review comments (by priority)
  max_summary: 25     # at most N rows in the summary table

# What fails the check. Read from the BASE branch.
gate:
  block_on: [CRITICAL, HIGH]
  fail_on_new: true   # only findings the PR introduces relative to base

# Per-rule overrides. Key by exact id or a glob; the most specific match wins,
# and an exact id always beats a glob.
rules:
  EXPLOIT-*:
    mode: comment     # block | comment | monitor
  EXPLOIT-AZURE-*:
    mode: block
  AGENT-EXEC-002:
    severity: CRITICAL
    enabled: true
  VIBE-PLACEHOLDER-006:
    enabled: false

# Paths Trishul never scans.
paths:
  ignore:
    - vendor/**
    - "*.min.js"
    - node_modules

# Opt in to experimental rules (full reports only; never shown inline).
experimental: false
```

## Fields

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `profile` | string | `default` | Named preset of defaults. |
| `comments.max_inline` | int | `10` | Max inline comments, chosen by priority. |
| `comments.max_summary` | int | `25` | Max summary-table rows. |
| `gate.block_on` | list | `[CRITICAL, HIGH]` | Severities that fail the gate. |
| `gate.fail_on_new` | bool | `true` | Gate only on PR-introduced findings. |
| `rules.<id\|glob>.severity` | enum | — | Override a rule's severity. |
| `rules.<id\|glob>.mode` | enum | — | `block` / `comment` / `monitor`. |
| `rules.<id\|glob>.enabled` | bool | `true` | Turn a rule off. |
| `paths.ignore` | list | — | Globs or bare segments to skip. |
| `experimental` | bool | `false` | Include experimental rules in reports. |

## Inline suppressions

Independently of this file, a finding can be suppressed at its location:

```go
doThing() // trishul-ignore[AGENT-EXEC-002]: accepted, tracked in TICKET-123
```

A reason is **required** — a reasonless marker does not suppress. Trishul also
honours `nosec`, `nosemgrep` and `gitleaks:allow` (each optionally naming a
rule). A marker on a line also covers the line directly below it.

## Inspecting the effective config

```
trishul-ci --explain-config
```

prints the merged configuration (defaults + your file) so you can see exactly
what will run.
