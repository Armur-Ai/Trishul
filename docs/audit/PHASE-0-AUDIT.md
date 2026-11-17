# Trishul — Phase 0 Repository Audit & Capability Matrix

**Audited commit:** `73e46d7` (local `main`, in sync with `origin/main`)
**Date:** 2026-11-17
**Method:** Read-only, evidence-grounded audit of the actual code across five slices (scan pipeline & safety, scanner adapters, findings/SARIF/secrets, MCP/PR/agent-security, tests/CI/claims). Every claim below carries a `file:line` reference. README/ROADMAP claims were *not* assumed correct.

> Scope reminder (new spec): six in-scope capabilities — SAST, SCA, Secrets, IaC, Code-flow/Taint, PR review. Out of scope: DAST, binary/RE, exploit development, fuzzing, symbolic execution, malware, network exploitation. Out-of-scope code already present must be **isolated and documented, not destructively removed**.

---

## 1. Executive summary — the headline truths

1. **The advertised primary workflow `trishul scan .` is BROKEN.** A local-directory scan errors out: *"directory scans are not supported by the CLI yet"* (`cli/internal/api/api.go:110-112`). Only single-file and repo-URL scans work.
2. **The CLI is not local-first.** `scan`/`run` are HTTP clients that POST to a separate `armur-server` process backed by **external Redis** (`cmd/server/main.go`, `cli/cmd/serve.go:138-168`, `internal/redis`). An embedded Redis exists but is never called (`internal/redis/embedded.go`). Only the (unreachable) MCP path runs scanners in-process.
3. **Secrets leak in plaintext.** TruffleHog's raw secret value is stored verbatim (`internal/tools/trufflehog.go:88`) and escapes via the JSON API (`internal/api/handlers.go:249`), Redis persistence (`internal/tasks/result_store.go:17`), and outbound webhooks (`internal/webhook/webhook.go Send`). **No redaction anywhere.** A unit test actively *asserts the leak* (`internal/tools/trufflehog_test.go:92-93`).
4. **Scanner failures are reported as success.** Missing/crashed tools are captured into `scan_errors` but the CLI suppresses that category entirely (`run.go:300`, `internal/models/convert.go:16`), so "all tools missing" is indistinguishable from "clean" — status stays `success`. No adapter does version/existence detection (zero `exec.LookPath`/`--version` in `internal/tools/`).
5. **Real taint / code-flow analysis does not exist.** No CodeQL, no Semgrep taint mode (`--config=auto` hardcoded), no dataflow engine. The only artifact is an **orphaned** CWE-presence chaining stub (`internal/attackpath/graph.go`, never imported). Capability #5 is effectively **Missing** — and it's the spec's #1 priority.
6. **Two read-only-safety footguns exist** (not currently reached, but fragile): in-place destructive file filtering (`pkg/utils.go:231` via `RunScanTaskLocal` `tasks.go:193`) and unconditional tree deletion (`tasks.go:306,550`). Safe today only by convention (MCP passes `language=""`; delete funcs are handed temp dirs).
7. **The agentic surface is written-but-unwired.** MCP server (`StartMCPServer` never called), PR review (`internal/agent/pr_review.go` has no caller; marks *all* findings "new"; no diff/SARIF/annotations/baseline), and agent-config security detection (**does not exist**).
8. **The repo's own docs are honest.** README/ROADMAP pre-emptively enumerate these gaps. The overclaims ("SAST+DAST+exploit simulation", "30+ tools", "15+ languages") survive only in **satellite artifacts** (`.goreleaser.yml`, npm/pip/vscode manifests, docs-site) and a **stale 14 MB old-brand Linux binary committed to git** (`cli/armur-cli`).
9. **CI is red on main** (since ~March per ROADMAP §2) due to a Go `1.24` (CI) vs `1.25.0` (go.mod) skew; the code otherwise **builds and root-module unit tests pass** with zero external deps.

---

## 2. Core capability matrix (the six)

| # | Capability | State | Evidence (what actually exists) |
|---|---|---|---|
| 1 | **SAST** | **Partial–Working** | Strong, wired orchestration: semgrep, gosec, bandit, eslint, spotbugs, pmd, cppcheck, flawfinder, brakeman all registered (`internal/tasks/tasks.go:337-459`) with structured JSON parse. But: no version detection, soft timeouts, parse-only tests (no detection fixtures), and JS/TS gets only Semgrep+ESLint. Semgrep runs `--config=auto` (community rules), not security/taint rulesets. |
| 2 | **SCA / dependencies** | **Partial** | Only trivy + osv-scanner are wired (advanced scan, `tasks.go:521-525`). The richer set — grype, govulncheck, `sca.go` (npm/pip/composer/cargo/bundler), `sbom.go` (CycloneDX/SPDX), terrascan — is **orphaned/unreachable**. dependency-check wired only for Java. No SBOM output reachable. No hallucinated-package detection. |
| 3 | **Secrets** | **Broken** | Functionally single-tool (TruffleHog only; gitleaks adapter is **orphaned/unreachable**). And it **leaks plaintext** (see §1.3). Highest-priority defect. |
| 4 | **IaC / config** | **Working** (best-covered) | checkov, tfsec, kics, hadolint, kube-linter, kube-score all wired + JSON parse (`tasks.go:467-513`). Gaps vs spec: no Supabase RLS / Firebase rules support; GitHub Actions hardening not covered; terrascan orphaned. |
| 5 | **Code-flow / Taint** | **Missing** | No real source→sink anywhere. Only an orphaned CWE-chaining stub (`internal/attackpath/graph.go`). Spec's #1 priority is absent. |
| 6 | **PR review** | **Unreachable / Broken** | CLI `review` is a print-only stub (`cli/cmd/review.go:48`); `internal/agent/pr_review.go` has no caller and scans the *whole head branch*, labeling **every** finding "new" (`pr_review.go:94-96`). No base-vs-head diff, no changed-line filtering, no SARIF, no PR annotations, no baseline suppression, no rename handling. There is **no `pr` CLI command** (the spec's `trishul pr --base main`). |

---

## 3. Cross-cutting subsystem matrix

| Subsystem | State | Evidence |
|---|---|---|
| `trishul scan .` (local dir) | **Broken** | `cli/internal/api/api.go:110-112` rejects directories. |
| scan single file / repo URL | **Working** | `api.go:103-161`; URL requires `--language` (`scan.go:184-187`). |
| `--deep` flag | **Missing** | Depth is `--advanced`; no `--deep`. |
| `--output/--format sarif` (CLI) | **Broken** | `--format` flag defined but never read; Run reads only `--output` (text/json) (`scan.go:173,217,735`). |
| Local-first / embedded (no server+Redis) | **Missing for `scan`** | HTTP→server→asynq→Redis required (`serve.go`, `queue_task.go:44`). Embedded Redis unwired (`internal/redis/embedded.go`). Embedded path exists only via `trishul mcp` (`internal/mcp/server.go:102-158`). |
| Optional-LLM | **Working** | AI is warnings-only in `doctor.go:152-164`; core scanning doesn't need it. |
| Tool invocation substrate | **Partial** | 71 direct `exec.Command` sites; only 9 `exec.CommandContext`. `withTimeout` (`tasks.go:53-69`) is a *soft* timeout — process not killed on expiry (leak). No shared runner / no capability descriptors. |
| Skipped-tool vs clean scan | **Broken (CLI)** | Captured in `scan_errors` internally but suppressed in all CLI output; status stays `success`. |
| Shared finding schema | **Partial** | `internal/models/finding.go:21-40`. Missing: data-flow field, scanner **version**; weak structured evidence (single `Snippet`). |
| SARIF generation | **Partial** | Valid 2.1.0 skeleton (`pkg/sarif/sarif.go:107`) but consumes only `security_issues` — SCA/IaC/**secrets** omitted; `ruleId`=CWE-only (→`UNKNOWN` collapse); **no `partialFingerprints`**; non-deterministic rule order. |
| Dedup / fingerprint | **Broken** | `ComputeID` (`finding.go:43-52`) and dedup key (`dedup.go:14-24`) are two different tuples, both **line-sensitive** (churn on unrelated edits); in-run only (no cross-run store). |
| Severity normalization | **Partial** | Shared `severity.go:NormalizeSeverity` is **orphaned**; each adapter inlines its own; unknown severities silently default to **INFO** (`severity.go:42-43`); a second divergent normalizer exists (`models/convert.go:154-169`). |
| MCP server | **Unreachable** | Implemented, stdio, 5 tools + 1 resource, **no shell-exec tool** (good). But `StartMCPServer` is never called by any binary (`internal/mcp/server.go:26`; CLI `mcp.go:50` is a comment). |
| Untrusted-content → LLM prompt | **Broken (injection-exposed)** | Scanned code + manifests interpolated raw into prompts with no fencing/guard (`internal/ai/explain.go:10-29`, `techdetect.go:181-183`). No execution of scanned instructions today. |
| GitHub Action | **Partial** | Composite `action.yml` likely **broken** (CLI ignores `--format`/file output). Reusable `armur-scan.yml` works via server+docker SARIF path but is old-brand and needs a published image. |
| Agent-config security | **Missing** | No detection of changes to CLAUDE.md/AGENTS.md/`.cursorrules`/MCP configs/hooks anywhere. |
| Tests | **Partial** | Builds; root unit tests pass — but **parse-only** (no adapter tested against real vulnerable code); only "vulnerable" fixtures (no clean/negative corpus); `cli/` has **zero** tests; 38 adapters untested; integration tests gated `INTEGRATION_TESTS=1`, 3 languages, assert status only. |
| CI | **Broken** | Real workflows but red on main (Go `1.24` vs `1.25.0` skew, `test.yml`). `release.yml` publishes to the `trishul` PyPI name (collision with an unrelated package). |
| Repo hygiene | **Broken** | 14 MB stale Linux `cli/armur-cli` committed; `.gitignore` misses the bare path. |

---

## 4. Scope reconciliation (out-of-scope code present)

**Isolate + document (do NOT delete per spec):**

| Item | Location | Reachability |
|---|---|---|
| Smart-contract (slither, mythril) | `internal/tools/{slither,mythril}.go` | **WIRED into default scan** when `language=="sol"` (`tasks.go:491,495`) — the only out-of-scope code actually reachable. |
| Exploit development | `internal/exploit/{generator,runner}.go` | Orphaned / unreachable. |
| DAST + sandbox | `internal/sandbox/{dast,sandbox}.go` | Orphaned / unreachable. |
| Binary/RE, fuzzing, network | `internal/tools/{binary,fuzzing,network}.go` | Orphaned / unreachable. |

**Dead-but-in-scope adapters to revive or remove (18 total):** gitleaks, grype, govulncheck, `sca.go`, `sbom.go`, terrascan, csharp, swift, crypto, pii, llmsecurity, depupdate, openapi, testgen, threatmodel (+ out-of-scope binary/fuzzing/network). Several directly fill current gaps (**gitleaks** → secrets redundancy; **govulncheck/grype/sca/sbom** → SCA depth).

**Overclaims to correct (code is honest; satellites are not):** `.goreleaser.yml:73`, `packages/npm/package.json:4`, `packages/pip/README.md:3`, `packages/vscode/package.json:4`, `docs/tools/supported-tools.md:3`, `docs-site/docs/Docs/Architecture.md:5`.

---

## 5. Prioritized implementation plan (grounded in the above)

### Phase 0 — Safety, honesty, and `scan .` (blockers; low-risk, high-value)
- **0.1 Secrets redaction (P0).** Redact/fingerprint the secret at source (`trufflehog.go:88`): store a masked preview + stable fingerprint, never the raw value. Audit all sinks (API/Redis/webhook/history-DB `scan.go:604-619`, `binary.go:116-123`). Fix the leak-asserting test and add **canary regression tests** that fail if any plaintext secret reaches any output.
- **0.2 Fix `trishul scan .`** — implement local-directory scanning end-to-end (the primary workflow).
- **0.3 Honest scanner status.** Add version/existence detection per adapter; surface `scan_errors` in CLI output; distinguish Completed-with-findings / Completed-clean / **Skipped(unavailable)** / Failed / Timed-out / Cancelled; never treat skip as clean.
- **0.4 Read-only hardening.** Guard the two destructive primitives: make `RemoveNonRelevantFiles` operate only on temp copies (never in-place), and assert delete targets are within the managed temp root. Add a test proving a scan never modifies the target tree.
- **0.5 Harden timeouts** — migrate `exec.Command` → `exec.CommandContext` so cancellation actually kills processes.
- **0.6 Repair CI** — align Go version (`1.25`), get main green; remove/relocate the 14 MB binary and fix `.gitignore`.
- **0.7 Correct satellite overclaims** to match the honest README/ROADMAP.

### Phase 1 — Reliable core (SAST/SCA/Secrets/IaC + normalization)
- Revive in-scope adapters that fill gaps: **gitleaks** (secrets redundancy), **govulncheck/grype/sca.go/sbom.go** (SCA depth + SBOM). Add per-adapter positive **and** negative fixtures.
- Switch Semgrep to security rulesets; stop counting code-quality tools (golint/gocyclo/radon/…) as security.
- Wire the shared severity normalizer; collapse the two divergent normalizers into one.
- Fix dedup/fingerprint to be **line-insensitive and stable** (hash semantic location, not raw line); emit `partialFingerprints` in SARIF; make SARIF consume SCA/IaC/secrets; deterministic rule ordering; add scanner version to the schema.

### Phase 2 — Deep code security (taint — the priority gap)
- Integrate a **real taint-capable engine** (Semgrep taint-mode rules and/or CodeQL packs) for JS/TS, Python, Go, Java; populate the schema's data-flow field with the actual supported source→sink path. Report "path incomplete" explicitly rather than inventing steps. Revive `attackpath` only as correlation *on top of* real flows, not as a substitute.

### Phase 3 — PR & agent security
- Implement a real `trishul pr --base <ref>`: base-vs-head diff, changed-file/line mapping, **new-vs-existing** via stable fingerprints (incl. flow/config-change awareness, not just changed lines), baseline suppression, rename handling, SARIF + GitHub annotations. Fix/retire the composite `action.yml`.
- Wire the MCP server into a shipped binary; keep the no-shell-exec constraint; add an **untrusted-content guard** so scanned code/manifests can't steer the model (fence + label; never execute instructions from scanned files).
- Build **agent-config change detection** (CLAUDE.md/AGENTS.md/`.cursorrules`/MCP configs/CI & install hooks) as evidence-based rules, treating repo instructions as untrusted data.

### Phase 4 — Product quality
- Investigate the **embedded/local-first execution mode** (wire the existing embedded Redis, or a queue-free in-process path) *while retaining* the supported server mode. Benchmark corpus (OWASP/Juliet + curated pairs), precision/recall measurement, packaging, docs, migration notes.

---

## 6. Key decisions that gate the work (for the owner)

1. **Architecture:** the spec wants *both* a local-first embedded mode **and** retained server mode. That's a real lift. Start by making the CLI run scanners in-process (reuse the MCP path) for `scan .`, keeping the server for CI/hosted — or keep server-only for now and just fix safety?
2. **Branding:** cobra root is already `trishul` but the binary/CI/docker/pip are `armur`/`trishul`-collision. Confirm full rename to `trishul` (incl. a non-colliding PyPI name).
3. **Out-of-scope smart-contract (slither/mythril)** is wired into the default scan. Gate it behind an opt-in flag (isolate) — confirm.
4. **Dead in-scope adapters:** revive (gitleaks, govulncheck, grype, sca, sbom…) vs remove. Recommend revive for the ones that fill gaps.

---

*This document is the Phase-0 deliverable ("initial repository audit with evidence" + "capability matrix before implementation"). A "capability matrix after" will accompany each implemented phase.*

---

## Appendix: capability matrix — after Phase 0 (in progress)

Tracks the deltas landed in the Phase-0 run. Items not listed are unchanged from the "before" matrix above.

| Area | Before | After |
|---|---|---|
| Secrets redaction | **Broken** — raw secret leaked via API/Redis/webhooks; test asserted the leak | **Fixed** — `internal/redact`; masked preview + fingerprint only; canary regression test |
| Read-only safety | Footguns, safe only by convention | **Guarded** — `SafeRemoveAll`/`IsManagedPath`; pruning no-ops on user paths; byte-identical invariant test |
| Per-tool timeout | Soft (process leaked) | **Hard kill** via `RunToolCommand` (`exec.CommandContext`) |
| Tool availability | None — missing tool → silent empty result | `ToolAvailable` + capability map; known-missing tools recorded as **skipped** and shown in the CLI |
| Execution outcome | Implicit | Structured `ToolOutcome` enum (`completed/skipped/failed/timed_out/cancelled`), logged per tool |
| Scanner adapters | Direct `exec.Command`, no timeout/availability | ~47 adapters routed through the helpers |
| SARIF | No fingerprints, random rule order, secrets omitted | **`partialFingerprints`** + deterministic order; **redacted secrets included** (CWE-798) |
| Smart-contract tools (out of scope) | Wired into default scan | Gated behind `TRISHUL_PROFILE=web3` |
| CI | Red on `main` (Go 1.24 vs 1.25) | Aligned to 1.25; build/vet/tests green |
| Repo hygiene | 14 MB binary committed | Removed; built binaries gitignored |
| BatchScan | Broken (scan-type literals) | Fixed (uses the constants) |
| Overclaims / brand | DAST/exploit/"30+ tools"; `armur` surfaces | Corrected across packaging/docs; MCP tools, Action, pre-commit, docs renamed to `trishul` |

**Still open (next):** `trishul scan .` / embedded engine (0.2/0.5), severity-normalizer unification (0.6), full `--profile` plumbing + quality-tool gating (0.7), per-detector fixtures, docker-image rename + PyPI collision (0.8).
