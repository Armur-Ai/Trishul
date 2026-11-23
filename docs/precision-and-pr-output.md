# Precision, findings quality & PR output: design

Companion to **Phase P** at the top of [`IMPLEMENTATION-PLAN.md`](IMPLEMENTATION-PLAN.md). That file holds the checkbox tasks; this one holds the reasoning, the competitive analysis and the target output mockups those tasks build toward.

## 1. Why this is the priority

On 2026-11-23 we scanned 190 popular MCP, agent and AI-starter repos (`~/Engineering/Trishul-reports/state-of-mcp-security/`, internal). A manual review of 50 high/critical findings found:

| | Share |
|---|---|
| Actionable true positives | **2%** (1/48) |
| Literally correct but benign or intended | 18% |
| False positives | **76%** |

Diff-aware PR mode reduces how **many** findings a developer sees, but not how **accurate** each one is. Codecov-style adoption depends on the PR comment being trusted: if the first comment a developer sees is wrong, the app gets uninstalled. So the order of work is:

1. **Measure:** a labeled corpus and per-rule precision in CI.
2. **Remove noise:** shared file and context classification, then fixes rule by rule.
3. **Make true positives more useful:** evidence, reachability, fixes.
4. **Then improve the presentation:** inline review comments, quality gate, commands.

Don't ship presentation polish on top of 76% noise.

### Ranked FP sources (from `false-positives.md`)

| Rank | Source | Volume | Root cause |
|---|---|---|---|
| 1 | SUPABASE-RLS-001/002 | 1,147 high | Runs on any SQL, not just Supabase projects. Migration history is ignored. Has a `IF NOT EXISTS` parser bug. Policies scoped `TO service_role` are flagged. |
| 2 | AGENT-OBFS-001/004 | 13,490 + 600 | Fires on every HTML comment, generator banner, RTL/bidi text and locale file. |
| 3 | Keyword rules (VIBE-LLM-002, AGENT-INSTR-004, AGENT-EXEC-002/003) | ~1,100 high | Matches inside comments, echo/usage text and negations ("do **not** leak keys"). `RegExp.exec` is taken for command execution. |
| 4 | AGENT-CHAIN-001 | fires in 43% of repos | Built from two low-confidence legs. |
| 5 | VIBE-AUTHZ-001/002 | 691 high | Doesn't see app-wide middleware or helper calls inside the handler. |
| 6 | Secrets | 90, 0 live | Matches UI placeholders, emulator demo keys, `PUBLIC_*` constants and image names. |
| 7 | EXPLOIT-* | 624 | Not limited to the right language (Java patterns in Go files). Runs on minified bundles. Reachability is ignored. |

## 2. How professional tools present results

Collected from the products' public docs and their PR output as commonly seen. Treat these as patterns to learn from, not specs to copy.

| Tool | What it does well | What Trishul should take from it |
|---|---|---|
| **Codecov** | One sticky PR comment with one headline metric and a delta, a compact "impacted files" table, and comment behaviour that is configurable (only when changed, edit vs. new). Separate statuses for the whole project and for the patch. | One summary comment, edited in place. Headline first ("2 new issues · 1 fixed"). Comment only when something changed. Gate on the **patch** (new code), not the repo. |
| **CodeRabbit** | A walkthrough/summary comment plus **inline review comments** anchored to diff lines, each with severity and a **committable suggestion**. Nitpicks are collapsed. Issues outside the changed lines go in their own section. Chat commands (`@coderabbitai …`). Dismissals are remembered as learnings. Review profiles from quiet to assertive. | Inline comments with GitHub `suggestion` blocks. A separate "outside the diff" section. `@trishul` commands. Dismissals that persist per repo. Quiet/balanced/thorough profiles. |
| **SonarQube Cloud** | A **quality gate** that only looks at new code ("Clean as You Code"). A small PR summary card with counts per dimension and one link to details. | A pass/fail gate on new findings only, with a short summary card and details behind a link. |
| **Semgrep** | Per-finding inline comments with the rule message and autofix. Triage by replying (`/semgrep ignore …`). Each rule has a policy mode: monitor, comment or block. | Per-rule policy modes (monitor/comment/block). Triage from inside the PR. Deterministic autofixes. |
| **Socket** | A dependency-change alert table with an ignore-by-comment command. Shows only what the PR changed in dependencies. | Agent supply-chain changes (new MCP servers, changed agent instructions) shown as their own "what changed" table. |
| **GitHub code scanning** | Alerts tracked over time. Dismissal reasons (false positive / won't fix / used in tests). Severity comes from `security-severity`. Autofix suggestions. | SARIF with `security-severity`, rule help markdown, `codeFlows` for chains and `fixes`. Dismissal reasons match GitHub's. |

**Principles we take from all of them:**
1. **One place to look.** The check run is the full record. The summary comment is short. Inline comments only appear on lines the PR changed.
2. **Headline first.** The first line answers "do I need to act?"
3. **Only what this PR changed.** The gate and the comments cover only new code.
4. **Every finding is actionable.** It explains why, shows evidence and suggests a fix, ideally one you can commit with a click.
5. **Triage happens in the PR,** and it is remembered.
6. **Quiet by default.** Silence on clean PRs, nothing below medium, and experimental rules are never shown on PRs.
7. **Consistent visual language.** The same severity icons and rule links everywhere.

## 3. Target output (mockups)

### 3.1 Summary comment (sticky; only when there are new findings, then kept up to date)

```markdown
<!-- trishul-pr-gate -->
### 🔱 Trishul · 2 new issues · 1 fixed
> ⚠️ **This PR changes files your AI coding agent reads** (`CLAUDE.md`, `.cursor/mcp.json`). Review them as code.

| | Issue | Where |
|---|---|---|
| 🔴 **Critical** | [Supabase table `orders` has no row-level security](https://armur.ai/trishul/rules/SUPABASE-RLS-001) | `supabase/migrations/0007_orders.sql:12` |
| 🟠 **High** | [MCP server launched without a pinned version](https://armur.ai/trishul/rules/AGENT-MCP-001) | `.cursor/mcp.json:5` |

Quality gate: **failed** (new critical). Inline suggestions are on the changed lines.
<details><summary>1 issue outside the changed lines · 41 pre-existing not shown</summary>…</details>

<sub>Reply `@trishul-security ignore <reason>` on any inline comment to dismiss it · [Full report](check-run-link) · [Configure](docs-link)</sub>
```

### 3.2 Inline review comment (on the diff line)

````markdown
🟠 **High · AGENT-MCP-001 · MCP server launched without a pinned version**

`npx -y @acme/mcp-server` runs whatever is published under that name next time your agent starts, with your agent's permissions.

```suggestion
      "args": ["-y", "@acme/mcp-server@1.4.2"]
```
<details><summary>Why this matters · references</summary>…</details>

<sub>Confidence: high · `@trishul-security ignore <reason>` · [rule docs](…)</sub>
````

### 3.3 Check run (full record)
- **Title:** `2 new issues (1 critical, 1 high) · gate failed`
- **Summary:**
  1. the headline;
  2. counts by severity and category;
  3. a "what changed in your agent surface" table (new MCP servers, changed instruction files, new permissions);
  4. every new finding grouped by category, with evidence;
  5. a mermaid diagram for agent attack chains;
  6. fixed findings;
  7. the config used, the scan duration, and the rule-pack version.
- **Annotations:** on the changed lines only.

### 3.4 Clean PR
Silence by default: the check reads **✅ No new issues** and there is no comment. If an earlier Trishul comment exists, it is edited to "All clear ✅".

## 4. Configuration surface (target)

```yaml
# .trishul.yml (read from the BASE branch for policy)
profile: balanced            # quiet | balanced | thorough
comments:
  summary: auto              # auto | always | off
  inline: high               # off | critical | high | medium
gate:
  block_on: critical         # off | critical | high
  min_confidence: high
rules:
  SUPABASE-RLS-003: { severity: low }
  VIBE-ABUSE-*: { mode: monitor }   # monitor | comment | block
paths:
  ignore: ["legacy/**"]
experimental: false
```

## 5. Metrics that define "done"

| Metric | Target before going public |
|---|---|
| Precision of high/critical findings on a random sample (two reviewers, ≥100 findings) | **≥ 80%** |
| Per-rule precision for every rule shown on PRs by default | **≥ 70%**, or the rule is demoted to experimental |
| Share of clean (no-real-issue) PRs that get a comment | **≤ 5%** |
| Median PR check time (App) | **≤ 30 s** |
| Dismissed as false positive in dogfooding (2 weeks, Armur-Ai repos) | **≤ 10%** of inline comments |
| 30-day retention of installed repos (from `/stats`) | tracked, ≥ 60% target |
