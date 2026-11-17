# AI Agent Supply-Chain Security

Trishul ships a dedicated subsystem for a threat that traditional SAST was never
designed to catch: **attacks that target the AI coding agent itself** rather than
the application it writes. It detects malicious instructions and execution paths
introduced through untrusted pull requests, repositories, dependencies, and
development tooling that are crafted to subvert agents such as Claude Code,
Cursor, Codex, and Copilot.

This analysis **runs as part of every scan** (it is one of the built-in,
dependency-free analyzers that execute on each run, read-only) and its findings
are emitted to CLI, JSON, and SARIF output alongside the rest.

## The threat model

A modern AI coding agent does far more than autocomplete. Asked to review or land
a pull request, it will typically:

1. Check out the branch into a workspace it can read and write.
2. Read repository "context" files — `CLAUDE.md`, `AGENTS.md`, `.cursorrules`,
   `.github/copilot-instructions.md`, and similar — and treat them as guidance.
3. Install dependencies, which runs package lifecycle hooks.
4. Run build, test, lint, and CI scripts.
5. Launch any configured MCP (Model Context Protocol) servers it has been told to
   trust, and call their tools.

Every one of those steps reads attacker-controllable text. A malicious pull
request does not need a memory-corruption bug — it can simply **plant content**:

- An instruction file that tells the agent to ignore its prior rules, exfiltrate
  secrets, or run a command.
- A prompt-injection directive hidden in a code comment, a README, a test
  fixture, or an issue/PR template that the agent reads as data.
- A package `postinstall` hook, Makefile target, or GitHub Actions step that
  fetches and runs remote code during install or CI.
- An MCP config entry that pulls unpinned/remote code onto the developer's
  machine or embeds a secret.
- A permission/sandbox config change that blanket-allows tools, disables the
  approval prompt, or passes a `--dangerously-*` / `--no-sandbox` flag.
- The same intent **encoded** — hidden with zero-width/bidirectional Unicode,
  homoglyphs, base64/hex blobs, or HTML/Markdown comments — so a human reviewer
  misses it but the agent still reads it.

The crossing of a **trust boundary** is the thing Trishul names: untrusted
repository content reaching a privileged agent workflow.

## Passive analysis — the core guarantee

The subsystem is **strictly passive**. Its analyzers:

- **Read files only.** They never execute, source, or interpolate any scanned
  instruction, hook, install script, or MCP server.
- **Treat all scanned text as data**, never as instructions to Trishul's own
  analysis. A prompt-injection payload in a file under scan cannot steer Trishul.
- **Keep evidence honest.** Evidence is a trimmed, descriptive excerpt of the
  repository's own text for a human to review — never a synthesized or executable
  payload. Secrets found in the process (for example in an MCP config) are
  reported redacted.

Even for the encoded/obfuscation checks, base64 and hex blobs are decoded
**in-process, for inspection only** — nothing recovered is ever run.

## The seven components

Components 1-6 are independent analyzers registered into the scan; a failing
component is skipped and never aborts the rest of the analysis. Component 7 is a
correlation pass that runs over the aggregated findings of the first six.

| # | Component | Check-ID family | What it flags |
|---|-----------|-----------------|---------------|
| 1 | Agent-instruction analysis | `AGENT-INSTR` | Instruction-override, authority impersonation, role escalation, and action directives in agent-instruction files (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.cursor/rules/*`, `.github/copilot-instructions.md`, `.claude/*`, `.windsurfrules`). |
| 2 | Prompt-injection detection | `AGENT-INJ` | Injection directives embedded in content the agent ingests as data — source-code comments, docs/README/fixtures, issue/PR templates — crafted to be read as instructions. |
| 3 | Command & execution-path analysis | `AGENT-EXEC` | Install/build/CI execution paths that fetch and run remote code, exfiltrate secrets/credentials, or reach new network destinations (package lifecycle hooks, shell/Makefile scripts, GitHub Actions workflows). |
| 4 | MCP server & tool trust | `AGENT-MCP` | Untrusted MCP config: unpinned auto-install runners (`npx -y`/`uvx`/`bunx`), servers that fetch and run remote code, embedded secrets (redacted), and newly-configured servers to review. |
| 5 | Permission & sandbox config | `AGENT-PERM` | Config that removes a safety gate: blanket allow-all tool permissions, disabled approval/confirmation, dangerous CLI flags (`--dangerously-*`, `--no-sandbox`), or disabled security checks. |
| 6 | Encoded-content & obfuscation | `AGENT-OBFS` | Instructions concealed from a human but readable by an agent: invisible/bidirectional Unicode, homoglyphs, base64/hex that decodes to instruction-like text, and directives hidden in HTML/Markdown comments. |
| 7 | Cross-file attack-chain correlation | `AGENT-CHAIN` | Links an individually-suspicious untrusted "entry" signal (e.g. a prompt injection) to an enabled "action" signal (e.g. an execution path or permission change) into one corroborated finding. |

### Check-ID families

Every finding carries a stable `check_id` so you can triage, suppress, and track
it. The families and their current rules:

- **`AGENT-INSTR-001..004`** — instruction override, system/developer
  impersonation, role/authority escalation, and action directives (exfiltrate,
  run commands, add network calls, disable checks).
- **`AGENT-INJ-001..003`** — directive embedded in a source-code comment,
  documentation/fixture, or issue/PR template.
- **`AGENT-EXEC-001..003`** — fetch-and-run remote code; secret/credential
  exfiltration; new network destination during install/build/CI.
- **`AGENT-MCP-001..004`** — unpinned auto-install runner; server fetches and
  runs remote code; secret embedded in MCP config (redacted); newly-configured
  server to review.
- **`AGENT-PERM-001..004`** — blanket allow-all; approval/confirmation disabled;
  dangerous sandbox-bypass flag; security check disabled.
- **`AGENT-OBFS-001..004`** — invisible/bidirectional Unicode; homoglyph
  confusables; base64/hex decoding to instructions; directive hidden in an
  HTML/Markdown comment.
- **`AGENT-CHAIN-001`** — correlated entry-to-action attack chain.

## Finding shape

Agent-security findings are intentionally richer than a generic SAST finding so
they can name the trust boundary being crossed and keep the evidence honest.
Each finding carries:

| Field | Meaning |
|-------|---------|
| `check_id` | Stable rule identifier (see families above). |
| `title`, `severity` | What was found and how serious (`CRITICAL`…`INFO`). |
| `confidence` | `HIGH` / `MEDIUM` / `LOW` — how strongly the evidence supports the claim. |
| `entry_point` | The untrusted source (the file/path the content came in through). |
| `trust_boundary` | The boundary being crossed. |
| `affected_workflow` | The agent workflow put at risk. |
| `enabled_action` | The action the content requests or enables. |
| `file`, `line` | Location in the repository. |
| `evidence` | Trimmed, descriptive excerpt(s) for a human to review. |
| `limitations` | An honest note on what the signal does and does not prove. |
| `remediation` | What to do about it. |
| `cwe` | CWE mapping where applicable (e.g. CWE-77 for command directives). |

## SARIF output

Agent-security findings are included in SARIF 2.1.0 output like every other
category. Each finding's `check_id` becomes the SARIF rule ID, and the trust
boundary and confidence are appended to the result message so they survive into
GitHub code scanning and other SARIF consumers. Findings carry stable
`partialFingerprints`, so they deduplicate across runs. See
[GitHub Actions integration](ci/github-actions.md) for uploading SARIF.

## Detection limitations — what we do NOT claim

This subsystem raises signals for a human to act on. It is deliberately honest
about its limits:

- **The semantic layer is heuristic.** Prompt-injection detection (Component 2)
  looks for directives that an attacker crafted to be read as instructions.
  On its own it can never justify a high-confidence claim — its confidence is
  capped at `MEDIUM`, and every such finding asks for corroboration.
- **Correlation corroborates; it does not prove.** An `AGENT-CHAIN` finding
  links an entry signal to an action signal. That raises confidence, but it is
  not proof that the agent will comply or that the entry point actually reaches
  the action in your specific workflow — confirm it yourself.
- **Suspicious text is not proof of compromise.** A flagged instruction, an
  unusual install hook, or an encoded blob is a reason to look, not a verdict.
- **The analysis is passive.** Trishul never executes the untrusted content,
  never launches an MCP server, and performs **no autonomous exploitation**.
  It reports what it reads.

## Status

The AI Agent Supply-Chain Security subsystem is actively developed and runs on
every scan today. A few things are honest to call out:

- It runs automatically as a built-in analyzer; there is **no separate flag or
  config** required to enable it.
- A **dedicated `trishul agent-security` CLI command** (to scan only this
  category and tune its output) is **planned**, not yet wired.
- Like the rest of Trishul, it analyzes a **repository URL or a file**; scanning
  a local directory straight from the CLI is not yet wired (build from source and
  scan a repo or a file for now).

If a finding here does not match what the code does, that is a bug — please open
an issue.
