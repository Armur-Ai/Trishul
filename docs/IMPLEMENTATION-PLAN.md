# Trishul — Implementation Plan

**The granular, checkbox-tracked execution plan.** The [`ROADMAP.md`](../ROADMAP.md) holds the general phases and the product bet; this document holds the tasks and sub-tasks under each phase, grounded in the [Phase-0 audit](audit/PHASE-0-AUDIT.md) of commit `73e46d7`.

- **Baseline audit:** [`docs/audit/PHASE-0-AUDIT.md`](audit/PHASE-0-AUDIT.md) — capability matrix + `file:line` evidence.
- **Architecture decision:** embedded in-process engine for `trishul scan .` (no Redis/server for the default path), **server mode retained** for CI/hosted/SARIF.
- **Scope:** SAST · SCA · Secrets · IaC · Code-flow/Taint · PR review. Out-of-scope code (DAST, exploit, fuzzing, binary, smart-contract) is **isolated behind opt-in profiles, not deleted**.

## How to use this file

- `[ ]` not started · `[~]` in progress · `[x]` done & tested. Update the box in the PR that lands the task.
- **✨ NEW** marks capabilities added beyond the original spec/roadmap — proposed enhancements that make Trishul materially better.
- Every task names its **acceptance check**. A box is only ticked when its check passes on a clean machine.
- Each phase ends with an **exit test** a stranger can reproduce. Phases are ordered by dependency, not date.

## Engineering invariants (apply to every task)

- [ ] The scan target is **read-only**: no task may write, move, delete, or filter files inside it. (Invariant test in Phase 0.3.)
- [ ] **No plaintext secret** may appear in any output sink, ever. (Canary test in Phase 0.1.)
- [ ] A **skipped/unavailable scanner is never a clean result** — it is surfaced as `skipped`.
- [ ] **No network during a scan** unless explicitly configured (tool downloads and DB updates are separate, opt-in steps).
- [ ] Scanned content is **untrusted data**: never executed, never allowed to steer Trishul's own LLM calls.
- [ ] Every new detector ships with **one vulnerable and one safe fixture**; CI fails if a listed tool has no passing fixture.

---

## Phase 0 — Make the promise true & make it safe (v0.1)

> Goal: a stranger can install Trishul and run `trishul scan .` on a real project, get honest results, and have their files untouched. Everything else depends on this.

### 0.1 Secrets redaction — **P0 blocker** (`internal/tools/trufflehog.go`, `pkg/format.go`, sinks)
- [x] Redact at the source: `formatSecretIssue` now emits `secret_preview` (via `redact.Mask`) + `fingerprint` (via `redact.Fingerprint`), never the raw value. New stdlib-only package `internal/redact` with full tests.
- [x] No raw-value field reaches the result map — `secret_preview`/`fingerprint` replace the `secret` key, so nothing downstream can receive the plaintext.
- [x] All sinks covered: the leak had a single source (`formatSecretIssue`); its map is the only path to the JSON API, Redis, and webhooks, so the one change closes every sink. (Verified trivy/binary carry no captured secret value; the webhook HMAC secret is unrelated and intentionally untouched.)
- [x] Replaced the leak-asserting test with the inverse assertion (raw value absent; preview + fingerprint present).
- [x] ✨ **Canary regression test** (`secret_canary_test.go`): a synthetic secret fed through categorize → convert → JSON-marshal; fails if the plaintext or an interior fragment survives. Runs under `go test`, so CI gates it once green.
- **Acceptance:** ✅ canary test passes; serialized result contains no plaintext.

### 0.2 Fix `trishul scan .` (local directory) end-to-end (`cli/internal/api/api.go:110-112`, `cli/cmd/scan.go`)
- [ ] Implement local-directory scanning (currently rejected). Route `.`/relative/absolute dir targets through the new embedded engine (0.5), not the file-upload path.
- [ ] Auto-detect languages & ecosystems per directory; make `-l/--language` optional everywhere (incl. repo URLs).
- [ ] Support monorepos (multiple ecosystems in one tree) — per-subtree detection.
- [ ] Add `--deep` as an alias/superset of `--advanced`; make `--advanced` a **superset** of the standard scan and count its findings in the summary (`scan.go` summary bug).
- **Acceptance:** `trishul scan .` on `examples/vibe-coded-app` returns findings; `trishul scan ./path/to/file` and `trishul scan <url>` still work.

### 0.3 Read-only hardening (`pkg/utils.go:202-238`, `internal/tasks/tasks.go`)
- [~] Guard `RemoveNonRelevantFiles` so it no-ops on any non-managed (user) path. _(Full switch to per-tool include-globs — so pruning is never needed at all — is deferred to a follow-up; the destructive behaviour on user source is already neutralised.)_
- [x] Guard every `os.RemoveAll` (`tasks.go:306,550,590`) via `utils.SafeRemoveAll`, which refuses any path outside a managed working root.
- [x] `RunScanTaskLocal` (`tasks.go:193`) can no longer mutate the target: its `RemoveNonRelevantFiles` call no-ops on the user path (not managed).
- [x] ✨ **Invariant test** (`pkg/readonly_test.go`): snapshots a fixture tree's per-file hashes and asserts a non-managed target is byte-identical after pruning; also confirms pruning still works inside a managed copy.
- **Acceptance:** ✅ invariant test passes; `SafeRemoveAll`/`IsManagedPath` unit-tested.

### 0.4 Honest scanner status (`internal/tools/*`, `internal/tasks/tasks.go`, `cli/cmd/{scan,run}.go`)
- [x] ✨ Conservative **capability map** (`capability.go`): required binary per tool + `RequiredBinary`/`IsToolSkippable`. _(min-version/licence/resource-limit fields are a follow-up; required-binary is in.)_
- [~] **Existence detection** done (`ToolAvailable` via `exec.LookPath`; runner records known-missing tools as skipped). _Version comparison (`--version` vs min) still to add._
- [x] ✨ **Structured execution result** enum (`result.go`): `completed_with_findings`/`completed_clean`/`skipped_unavailable`/`failed`/`timed_out`/`cancelled` + `ClassifyOutcome`.
- [x] Surface `scan_errors` and skipped tools in CLI output (`scan.go printScanErrors`); the runner now emits a skip for known-missing tools (`tasks.go withTimeout`).
- [~] Migrate `exec.Command` → `exec.CommandContext`: helper `RunToolCommand[Stdout][InDir]` done (real process-kill timeout + availability); **adapter migration in progress** (delegated).
- **Acceptance:** ✅ a known-missing tool is reported as skipped (not clean) in the CLI output and `scan_errors`.

### 0.5 Embedded engine for the default path (`cli/`, `internal/tasks`, `internal/engine` ✨ new)
- [ ] ✨ Extract the scan pipeline into an importable **`internal/engine`** library callable in-process (no HTTP, no Redis).
- [ ] Make the CLI call the engine directly for `scan`; keep `trishul serve` for the API/CI use case.
- [ ] Wire the existing **embedded Redis** (`internal/redis/embedded.go`, currently dead) OR a queue-free in-process worker pool for local runs; remove the hard Redis dependency from the default path.
- [ ] Keep the server + asynq + SARIF-API path working (used by `armur-scan.yml`); add a regression test for it.
- **Acceptance:** `trishul scan .` works with no Redis and no server process running.

### 0.6 Findings normalization & SARIF correctness (`internal/models`, `internal/tools/severity.go`, `pkg/sarif`)
- [x] **Severity normalizers unified**: one canonical `models.NormalizeSeverityString`; `tools.NormalizeSeverity` delegates its generic path to it; `models.normalizeSev` too. No divergent copy. (Avoided the cycle by putting the shared map in the low-level `models` package.)
- [ ] Add missing schema fields: **scanner version**, **data-flow/trace** (for Phase 1), structured evidence. _(ToolVersion helper exists; wiring into findings pending.)_
- [x] ✨ **Line-insensitive, unified fingerprint**: `Finding.ComputeID` now hashes Tool|File|RuleID|normalized-Message (no raw line); the dedup key is aligned to the same basis. SARIF `partialFingerprints` likewise line-insensitive.
- [x] SARIF: `partialFingerprints` + **deterministic rule ordering** + **consumes all categories** (security, secrets-redacted, SCA, IaC) with stable per-rule ids (no `UNKNOWN` collapse).
- **Acceptance:** ✅ SARIF carries stable fingerprints, reproducible ordering, and full category coverage; severity + finding-identity unified.

### 0.7 Profiles & signal-over-volume (`internal/tasks`, `cli`)
- [x] ✨ **Profiles** `security` (default) / `quality` / `web3` / `all`, selectable via `--profile` (exported as `TRISHUL_PROFILE`, inherited by the auto-started server) and classified in `internal/tools/profiles.go`.
- [x] Default profile **omits** golint/gocyclo/radon/pydocstyle/vulture/godeadcode/jscpd/cargo-geiger (the runner skips quality tools unless `quality`/`all`); smart-contract tools stay behind `web3`.
- **Acceptance:** ✅ default scan runs security tools only; `--profile quality|web3|all` opts in; gating unit-tested.

### 0.8 Truth in packaging, branding & CI (`.github/workflows`, `action.yml`, `packages/*`, `cli/armur-cli`)
- [x] Fix CI: align test/lint/release workflows to Go `1.25` (the skew that reddened `main`).
- [x] Remove the committed **14 MB `cli/armur-cli`** binary; gitignore built binaries.
- [x] Correct overclaims in satellite artifacts (`.goreleaser.yml`, npm/pip/vscode manifests, `docs/tools/supported-tools.md`, docs-site Architecture) to match the honest README.
- [~] `armur → trishul` rename: MCP tool names ✅, Action ✅, pre-commit hooks ✅, docs-site ✅; config file already canonical `.trishul.yml` (legacy fallback) ✅. _Remaining: docker image refs, the PyPI `trishul` collision._
- [ ] Hide CLI commands whose backends aren't wired (`review`, `explain`, `fix`); fix/remove the dead `--diff`/`--staged-only` flags.
- [x] Fix `BatchScan` scan-type literal mismatch (used the string literals, worker switches on the constants).
- **Acceptance:** ✅ CI aligned/green, binary removed, overclaims corrected, BatchScan fixed; a few rename tails + command-hiding remain.

**Phase 0 exit test:** on clean macOS and Ubuntu, `trishul scan .` against `examples/vibe-coded-app` finishes <60 s, reports the planted findings, leaves the directory byte-identical, surfaces any skipped tools, leaks no plaintext secret, and makes no network calls beyond opt-in tool/DB updates.

> **Exit-test status (this run):** leaves the directory **byte-identical** ✅ (invariant test), **leaks no plaintext secret** ✅ (canary test), **surfaces skipped tools** ✅, **green build/test/CI** ✅. **Still required:** `trishul scan .` must actually run (needs the embedded engine, 0.2/0.5) — the one remaining blocker before the full exit test can pass end-to-end.

---

## Phase 1 — Reliable core + vibe-native detection (v0.2–v0.3)

> Goal: the six capabilities each have genuinely-wired, structured, tested adapters, plus Trishul's own rule packs for the Vibe Top 10. This is the moat.

### 1.1 Revive the in-scope dead adapters (18 orphaned — see audit §4)
- [ ] Secrets: wire **gitleaks** (currently orphaned) for redundancy + git-history scanning alongside TruffleHog.
- [ ] SCA: wire **govulncheck, grype, `sca.go`** (npm/pip/composer/cargo/bundler), **`sbom.go`** (CycloneDX/SPDX), and dependency-check beyond Java.
- [ ] Decide per adapter: revive vs remove (csharp, swift, openapi, testgen, threatmodel, depupdate) — track decisions in the PR.
- **Acceptance:** each revived adapter is registered, parses structured output, and has positive+negative fixtures.

### 1.2 SAST engine & rule packs (`internal/tools/semgrep.go`, new rule dir)
- [ ] Stop `--config=auto` (network + licence risk); ship a **pinned, licence-clean rule set**, offline by default. Evaluate **Opengrep** as the default engine.
- [ ] Add the ESLint security stack (eslint-plugin-security, no-unsanitized, @next/eslint-plugin-next) for the core JS/TS case.
- [ ] ✨ Confidence scoring per finding; auto-suppress `test/`, `vendor/`, generated, and `node_modules` paths by default.

### 1.3 Taint / code-flow — **spec priority, currently Missing** (Phase 2 in spec, pulled forward)
- [ ] Integrate a **real source→sink engine** (Opengrep/Semgrep taint-mode rules; evaluate CodeQL packs where licence permits) for JS/TS, Python, Go, Java.
- [ ] Populate the schema's **data-flow field** with the actual supported path; when a path can't be completed, report the limitation explicitly — **never invent steps with an LLM**.
- [ ] Rebuild `internal/attackpath` as correlation **on top of** real flows, not a substitute.
- [ ] Vuln classes: SQLi, command injection, SSRF, path traversal, unsafe deserialization, XSS, unsafe-exec, missing-authz (where evidence exists).
- **Acceptance:** a cross-file SQLi fixture yields a finding whose evidence shows the real source→sink path.

### 1.4 Vibe-native analyzers (build-ourselves moat — maps to Vibe Top 10)
- [x] **V01 client-secret exposure** (`internal/tools/clientsecrets.go`): secret-shaped values behind `NEXT_PUBLIC_`/`VITE_`/`EXPO_PUBLIC_`/`REACT_APP_`; service-role JWT / private key in client-side files; committed `.env` secrets. Emits only redacted previews (no-leak test). Wired on every scan; e2e-tested through the engine. _(Early in Phase 0 as a built-in, dependency-free analyzer.)_
- [x] **V03 open data layer — Supabase** (`internal/tools/supabase.go`): RLS off, `using (true)`, `anon` grants, `security definer` w/o `search_path`, public buckets (SUPABASE-RLS-001..005). Wired + e2e-tested. _(Firebase rules analyzer still to do.)_
- [ ] **V02 missing authorization:** route inventory for Next.js (`app/**/route.ts`, `pages/api/**`, server actions), Express, FastAPI, Flask, Hono, Supabase Edge Functions; flag data handlers with no session/token check; IDOR heuristic.
- [ ] **V04 dependency intelligence:** ✨ hallucinated/typosquat/dependency-confusion scoring (registry existence, age <30 days, download volume, edit-distance to popular names); OSV `MAL-` + GuardDog heuristics; offline snapshot of popular names.
- [ ] **V06/V07/V08 placeholder & abuse:** hardcoded JWT/session secrets, default creds, `verify=False`, `cors({origin:"*"})` with credentials, debug flags, security `TODO`s; unverified Stripe/Clerk/Svix webhooks; prices/roles trusted from request body; missing rate-limit on auth/LLM routes.
- [ ] **V09 unsafe LLM integration:** replace `llmsecurity.go` regex with taint rules (user input → prompt; model output → eval/SQL/shell/HTML); browser-side provider keys.
- **Acceptance:** each Vibe Top 10 class has ≥1 rule with vulnerable+safe fixtures; default profile = zero findings on safe variants.

### 1.5 Reporting & DX
- [ ] Rebuild the text report (file+line, full message, one row/finding, totals that match).
- [ ] Plain-English output: what it is, why an attacker cares, the fix; Vibe Top 10 ID + CWE per finding.
- [ ] ✨ **Launch-readiness score** with the top-3 things to fix first.
- [ ] ✨ `.trishul.yml` **policy-as-code**: severity gates, path ignores, rule enable/disable, documented.

**Phase 1 exit test:** on the fixture corpus, every Vibe Top 10 class fires on its vulnerable fixture and stays silent on its safe fixture; `trishul scan .` is reproducible (same input → same fingerprints).

---

## Phase 2 — In the agent loop (v0.4)

> Goal: Trishul becomes part of how AI-written code is made — in Claude Code, Cursor, Copilot, Codex.

### 2.1 MCP server that ships (`internal/mcp` — currently unreachable)
- [ ] Wire `StartMCPServer` into a real binary (`trishul mcp`); rename tools `armur_* → trishul_*`.
- [ ] Narrowly-scoped tools: scan project, scan changed files, retrieve findings, explain a finding, propose a remediation, ✨ **verify a proposed fix** (apply in a scratch copy, re-scan, confirm it closes the finding and adds none).
- [ ] Keep the hard **no-shell-exec** constraint (already satisfied); document the tool permission surface.
- **Acceptance:** Claude Code/Cursor can call `trishul` MCP tools; no tool grants arbitrary command execution.

### 2.2 Prompt-injection safety for Trishul's own AI (`internal/ai/*` — currently unguarded)
- [ ] ✨ **Untrusted-content guard:** fence and label scanned code/manifests in prompts (`explain.go`, `techdetect.go`); separate system instructions from scanned data; never execute model-suggested commands (`techdetect.go` RunCommand/BuildCommand stay inert).
- [ ] No secrets/proprietary source sent to an external model without explicit authorization (reuse the redaction layer).
- **Acceptance:** an adversarial fixture (a file containing "ignore previous instructions…") does not alter Trishul's analysis or trigger any action.

### 2.3 Editor & shell hooks
- [ ] `trishul hooks install`: Claude Code `PostToolUse` (scan after edit) + `Stop` (block on new critical) hooks; Cursor equivalent.
- [ ] Pre-install guard: check `npm/pip/npx` targets against dependency intelligence before they run (fixes the dead `--staged-only` pre-commit path).

### 2.4 Agent-surface security — **spec requirement, currently Missing** (V10)
- [ ] ✨ `trishul agent-scan`: evidence-based detection of suspicious changes to `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, agent skills, MCP configs, coding-agent hooks, CI workflows, install/build hooks — hidden/bidirectional Unicode, injected instructions, expanded tool permissions, disabled checks, new network destinations, install-time code execution, unpinned `npx -y`/`uvx` MCP servers, secrets in MCP config.
- [ ] Treat these files as untrusted data; **never execute** instructions found in them; evidence-based, not keyword-blocking.
- **Acceptance:** a benign agent-config change is clean; a malicious one (hidden Unicode / permission escalation) is flagged with evidence.

### 2.5 Fix loop & guard rules
- [ ] `trishul fix --prompt`: paste-ready fix prompt (file, line, vulnerable code, required property of the fix, how to verify) — no API key needed.
- [ ] `trishul guard`: write a stack-tailored security section into `CLAUDE.md`/`AGENTS.md`/`.cursor/rules`/`copilot-instructions.md`.
- [ ] ✨ **AI-provenance mode:** identify AI-authored commits; `trishul scan --ai-authored` scans only that code; reports break findings down by author type.

**Phase 2 exit test:** in a recorded session, an agent writes a Supabase table without RLS, the hook fires, the agent receives the finding and the verify-loop confirms the fix — with no human typing.

---

## Phase 3 — PR review & scanner breadth (v0.5)

> Goal: a diff-aware PR gate that distinguishes new from pre-existing findings, plus broader, benchmarked tool coverage.

### 3.1 PR / diff-aware review (`internal/agent/pr_review.go` — currently stub; marks all findings "new")
- [ ] Real `trishul pr --base <ref>`: base-vs-head scan + comparison (not whole-head-branch).
- [ ] Changed-file/line mapping; **new vs pre-existing** via the stable fingerprints from 0.6.
- [ ] ✨ Keep findings that are newly-introduced via **changed data-flow or config** even on unchanged lines (don't discard everything outside the diff).
- [ ] Baseline suppression with an auditable baseline file; rename/move handling.
- [ ] SARIF output + GitHub PR annotations/inline comments; configurable severity policy & exit codes.
- [ ] Fix the composite `action.yml` (CLI must honor `--format`/file output) or converge on the server-based `armur-scan.yml` path; publish a Marketplace Action with SARIF upload.
- **Acceptance:** a PR that introduces a vuln is flagged as *new*; a pre-existing one is not re-reported; annotations appear inline.

### 3.2 Scanner breadth (per ROADMAP §8 expansion plan)
- [ ] Tier-1/2 additions, each with pinned version, provisioning entry, normalizer, fixture, Vibe Top 10 mapping: ast-grep, Ruff `S`, njsscan, zizmor/actionlint (CI hardening — spec's insecure-GitHub-Actions requirement), Squawk, Splinter (live Supabase), Syft (SBOM), retire.js, GuardDog, Snyk agent-scan.
- [ ] ✨ Generate the README tool matrix **from the registry in code**; CI fails if a listed tool has no passing fixture.
- [ ] `trishul tools install`: pinned, checksummed downloads into `~/.trishul/tools` (no `pip/go install` at scan time); `--docker` fallback runs the same pipeline.
- **Acceptance:** the tool matrix is code-generated and every listed tool has a passing fixture.

---

## Phase 4 — Proof & distribution (v0.6–v1.0)

> Goal: public, reproducible evidence that Trishul catches what AI coding tools generate.

- [ ] ✨ **VibeBench:** fixed app prompts run through each major AI coding tool; commit outputs, scan them, publish numbers + method. Doubles as the precision/recall harness (OWASP Benchmark/Juliet where applicable + curated vuln/fixed pairs).
- [ ] "State of Vibe-Coded Security" report, refreshed quarterly.
- [ ] ✨ **Reachability/exploitability triage + VEX:** emit OpenVEX statements (reachable/affected/not-affected) to cut dependency-noise; "confirmed reachable" vs "possible".
- [ ] ✨ **Incremental/cached scans:** content-hash cache keyed by file+tool+rule-version for fast re-scans; changed-files mode.
- [ ] Web scan at trishul.dev (paste a public repo URL → report); "Scanned by Trishul" badge with grade.
- [ ] VS Code / Cursor / Windsurf extension (one codebase); docs site matching the product; `CONTRIBUTING.md` rule-writing guide.
- **Acceptance:** VibeBench recall above an agreed bar for every Vibe Top 10 class and FP rate on the safe corpus below an agreed bar (bars set from the first run).

---

## Phase 5 — Runtime verification (after v1.0, demand-driven)

> Out-of-scope for the current upgrade; isolated code stays in-tree. Returns here as *verification of static findings*.

- [ ] `trishul probe <url>` for owned apps only (ownership proof required): exposed `.env`/`.git`, source maps, keys in bundles, anon-readable Supabase tables, open Firebase, headers.
- [ ] Wire the isolated sandbox/DAST/exploit packages **only** to confirm static findings ("confirmed exploitable" vs "possible").
- [ ] Attack-path view built on confirmed findings.

---

## Cross-cutting tracks (run continuously)

- **Security of the scanner itself:** read-only invariant, secret redaction, prompt-injection guard, no-network-by-default, no-shell-exec MCP, supply-chain-pinned tool installs.
- **Testing & benchmark:** per-adapter positive+negative fixtures; the canary secret test; the read-only invariant test; the reproducibility test; VibeBench as the precision/recall harness. **No invented benchmark numbers.**
- **Determinism & provenance:** every scan emits a manifest (tool versions, rule-pack version, vuln-DB freshness, profile, skipped tools) so results are reproducible and auditable.
- **Docs honesty:** nothing is advertised before its phase exit test passes; the README status table stays truthful.

---

## Target capability matrix (definition of done)

| Capability | Today | Target (this plan) |
|---|---|---|
| SAST | Partial | Working+tested, pinned rules, taint-capable engine |
| SCA | Partial | Working+tested, SBOM + hallucinated/malicious-pkg intel |
| Secrets | **Broken (leak)** | Working+tested, **redacted everywhere**, gitleaks+trufflehog |
| IaC | Working | Working+tested + Supabase RLS / Firebase / CI-hardening |
| Taint / code-flow | **Missing** | Working, real source→sink evidence paths |
| PR review | Unreachable | Working, diff-aware, new-vs-existing, SARIF + annotations |
| Agent-config security | **Missing** | ✨ Working, evidence-based, untrusted-by-default |
| Local-first `scan .` | **Broken** | Working, embedded, no Redis/server needed |

*Each phase ships with a refreshed "capability matrix — after" appended to the audit doc, per the deliverables list.*

---

## Capability 7 — AI Agent Supply-Chain Security (`internal/agentsec`)

> **Incremental extension, not a new project.** Deepens the agent-surface work (Phase 2.4). **Reuse** the PR diff engine (Phase 3.1), the shared `Finding` schema + stable fingerprints, the SARIF/annotation/MCP reporting, and the existing config parsing. No duplicate scanners or pipelines. New home: `internal/agentsec` (deterministic parsers + a semantic layer + a correlation graph), wired into the normal scan pipeline and a dedicated `trishul agent-security` command. Passive by default; an external LLM is never mandatory.

### Threat model (encode as fixtures, §F)
- [ ] Attacker controls PR content (source, comments, Markdown, test fixtures, package scripts, CI workflows, agent-config, MCP config) but **not** trusted host policies.
- [ ] Protected agent workflows: review PR · checkout PR · read repo instructions · run tests/builds · install deps · invoke tools · propose/apply changes.
- [ ] For each workflow, enumerate the **trust boundary** (untrusted repo content → agent action) the analysis reasons about.

### Component 1 — Agent instruction analysis
- [x] Structural parse of `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.cursor/rules/*`, `.github/copilot-instructions.md`, Claude/Cursor skills, hooks config.
- [x] Detect instruction-override / system-or-developer-message impersonation / authority-escalation language (e.g. "ignore previous", "you are now", fake "SYSTEM:"/"DEVELOPER:" framing) — reported as *suspicious instruction*, never "agent compromised".
- **Acceptance:** malicious instruction-file fixtures flagged with file/line + trust-boundary; benign instruction files clean.

### Component 2 — Prompt-injection detection (semantic layer)
- [x] Heuristic + optional-LLM detection of injection in comments, README/Markdown, test fixtures, tool-output-laundered text. The semantic layer is **never the sole basis for a high-confidence claim** (must be corroborated by a deterministic/correlation signal).
- [x] Treat all scanned text as data; Trishul's own analysis must not follow it.
- **Acceptance:** source-comment and doc injection fixtures flagged; a security-research doc *describing* injection is not a false positive.

### Component 3 — Command & execution-path analysis
- [x] Parse `package.json` scripts (pre/post-install), `Makefile`, shell scripts, build files, and `.github/workflows/*` for install-/build-time code execution, suspicious `curl|sh`, new network destinations, credential access.
- **Acceptance:** unsafe install/build hook + suspicious CI fixtures flagged with the executable path and the destination.

### Component 4 — MCP server & tool trust analysis
- [x] Parse MCP config (`.mcp.json`, `.cursor/mcp.json`, `mcp.json`, client configs): flag newly-registered/untrusted MCP servers, unpinned `npx -y`/`uvx` launchers, servers fetching remote code, and secrets embedded in MCP config.
- **Acceptance:** malicious MCP-config-change fixtures flagged; a pinned, known server is clean.

### Component 5 — Permission & sandbox configuration analysis
- [x] Detect permission-policy widening / sandbox weakening in agent configs (blanket allow-lists, disabled approvals, `--dangerously-*` flags, expanded tool scopes, disabled security checks).
- **Acceptance:** permission-escalation fixtures flagged with the before→after delta.

### Component 6 — Encoded-content & obfuscation analysis
- [x] Detect concealed instructions: hidden/bidirectional Unicode, zero-width chars, base64/hex/rot blobs that decode to instruction-like text, HTML/Markdown comment hiding, homoglyphs.
- **Acceptance:** encoded-instruction fixtures flagged (decoded conceptually, not executed); ordinary base64 assets not over-flagged.

### Component 7 — Cross-file PR attack-chain correlation
- [x] Build a graph linking: untrusted content → agent-consumption entry point → requested action → executable script → tool permission → sensitive resource → network destination → security control.
- [x] Emit **attack-chain findings** combining individually-low-risk changes; each finding states entry point, suspicious change, affected workflow, trust boundary, enabled action, file/line refs, confidence + **limitations**, remediation.
- **Acceptance:** a multi-file chain fixture (e.g. README injection → new npm postinstall → exfil URL) produces one correlated finding with the full path; unrelated benign changes do not chain.

### Safe analysis invariants (§D)
- [x] Passive by default: never execute untrusted instructions/hooks/install scripts/MCP servers. Any dynamic validation is opt-in, in a disposable sandbox with no prod creds, restricted FS/network, explicit authorization.
- [x] Secret canaries never appear in reports or external-model requests (reuse `internal/redact` + the canary test).

### CLI, reporting & integration (§G)
- [ ] Dedicated `trishul agent-security scan .` / `pr --base main` commands. _(Deferred: the CLI is a separate Go module that can't import `internal/agentsec`; lands with the CLI↔engine module-merge. Agent-security already runs inside every `trishul scan`.)_
- [x] Findings via CLI (rendered) + JSON + **SARIF** (check_id rule + trust-boundary + partialFingerprint); mapped to CWE-77/94/829/506/798. _(GitHub PR annotations + MCP tools: with PR mode / the module-merge.)_
- [x] Folded into the normal scan pipeline as a built-in, dependency-free analyzer set (runs read-only, no external LLM required).

### Benchmark (§F)
- [x] `testdata/agentsec/benchmark/` paired benign + malicious PR fixtures (incl. the hard security-research false-positive case) + a precision/recall/FP benchmark test. Measured recall 1.0 / precision 1.0 / 0 FP on this corpus; thresholds pinned at the measured values (not invented), limitations documented (small clean corpus, not a borderline stress test).

### Definition of done (§H)
- [x] Components parse configs structurally; attack chains carry verifiable evidence (AGENT-CHAIN-001 e2e-tested); no untrusted code executed (passive); secret canaries never leak (redaction + tests); **measured** malicious-vs-benign accuracy via the benchmark; docs state limitations. _(GitHub PR annotations + the dedicated CLI command remain, gated on the module-merge.)_
