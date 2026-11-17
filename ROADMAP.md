# trishul roadmap

**The open-source security scanner for AI-generated code.**
Find vulnerabilities in Cursor, Claude Code, Copilot and Windsurf generated applications before they reach production.

This document replaces the 59-sprint `IMPROVEMENTS.md` plan (archived at
[`docs/archive/IMPROVEMENTS-legacy.md`](docs/archive/IMPROVEMENTS-legacy.md)). That plan was written for
"Armur, a general security agent" and optimised for breadth. This one is written for one bet:
**own the vibe-coding security category**, and cut everything that does not serve it.

> **This roadmap holds the general phases and the bet.** The granular, checkbox-tracked task
> breakdown lives in [`docs/IMPLEMENTATION-PLAN.md`](docs/IMPLEMENTATION-PLAN.md), grounded in the
> evidence-based [`docs/audit/PHASE-0-AUDIT.md`](docs/audit/PHASE-0-AUDIT.md).

Last reviewed: 2026-11-17.

---

## Contents

1. [The bet](#1-the-bet)
2. [Where we actually are](#2-where-we-actually-are)
3. [Who we are building for](#3-who-we-are-building-for)
4. [The landscape and our wedge](#4-the-landscape-and-our-wedge)
5. [The Vibe Top 10](#5-the-vibe-top-10)
6. [Product pillars](#6-product-pillars)
7. [Phases](#7-phases)
8. [Scanner expansion plan](#8-scanner-expansion-plan)
9. [What we are cutting](#9-what-we-are-cutting)
10. [Go-to-market](#10-go-to-market)
11. [Risks](#11-risks)
12. [Open decisions](#12-open-decisions)
13. [Immediate priorities](#13-immediate-priorities)

---

## 1. The bet

AI assistants now write a large share of committed code, and that code is not getting safer:

- Veracode's 2026 GenAI Code Security Report puts the security pass rate of AI-generated code at
  **56%**, unchanged from the year before, across 100+ models. Syntax pass rate is near 100%.
  ([Veracode](https://www.veracode.com/news/llms-are-getting-smarter-but-not-safer-veracode-2026-genai-code-security-report-finds-ai-generated-code-security-has-stalled-at-56%25-pass-rate/))
- CodeRabbit's analysis of 470 open-source pull requests found AI co-authored PRs carry about
  **1.7x more issues** than human-only PRs, with XSS up to 2.74x.
  ([CodeRabbit](https://www.coderabbit.ai/blog/state-of-ai-vs-human-code-generation-report))
- A USENIX Security 2025 study of 16 code models found **19.7% of recommended packages did not exist**
  (205,474 unique hallucinated names), which is the raw material for slopsquatting.
  ([USENIX](https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen))
- CVE-2025-48757: **170 of 1,645** scanned Lovable-generated apps exposed data through missing
  Supabase row-level security.

The failure modes are specific and repetitive. Generic SAST was built for human-written enterprise
code and misses most of them: it does not know that a Supabase table has no RLS policy, that an
`npm install` line names a package that has never existed, or that `.cursorrules` contains
invisible instructions.

**The bet:** the winner of this category is the tool a developer can run in ten seconds, that
understands the stack AI tools actually generate, and that feeds its findings straight back to the
agent that wrote the code. It is open source, local-first, and has a named taxonomy everyone else
ends up citing.

---

## 2. Where we actually are

Re-audited against `main` at `73e46d7` on 2026-11-17, read-only and evidence-based across the
whole tree. Full detail with `file:line` evidence and a capability matrix is in
[`docs/audit/PHASE-0-AUDIT.md`](docs/audit/PHASE-0-AUDIT.md); this is the honest summary.

**What is genuinely good.** The code builds and the root-module unit tests pass with no external
dependencies. IaC scanning is the best-covered capability (checkov, tfsec, kics, hadolint,
kube-linter, kube-score all wired). SAST orchestration is real (semgrep, gosec, bandit, eslint,
spotbugs, pmd, cppcheck, flawfinder, brakeman). And — unusually — the README and this roadmap are
honest: they already enumerate the gaps below. The remaining overclaims survive only in satellite
artifacts (`.goreleaser.yml`, the npm/pip/vscode manifests, docs-site) and a stale committed binary.

**What must be fixed first (Phase 0).**

- **`trishul scan .` is broken.** Local-directory scans are rejected outright; only single-file and
  repo-URL scans work. The advertised primary workflow does not run.
- **Not local-first.** `scan` is an HTTP client to a separate `armur-server` backed by external
  Redis; the embedded Redis exists but is never wired. Only the (unreachable) MCP path runs
  in-process.
- **Secrets leak in plaintext.** TruffleHog's raw value is stored and escapes via the JSON API,
  Redis, and outbound webhooks; there is no redaction, and a test actually asserts the leak. P0.
- **Scanner failures read as success.** No adapter checks whether its binary exists; a missing tool
  yields empty results, and the CLI suppresses the error channel, so "all tools missing" looks like
  "clean".
- **Two read-only footguns** (in-place file filtering + unconditional tree delete) are safe today
  only by convention; one future caller = deletion of user source.
- **The agentic surface is written but unwired:** the MCP server is never started, PR review is a
  stub that marks every finding "new", and agent-config change detection does not exist.
- **Real taint / code-flow analysis is absent** (only an orphaned CWE-chaining stub) — the biggest
  single capability gap.
- **CI is red on `main`** (Go 1.24 vs 1.25 skew), a 14 MB old-brand binary is committed, and the
  `armur → trishul` rename is only half done.

### The honest summary

Trishul is a well-tested orchestration engine with a good CLI shell and a lot of unconnected
feature code — a strong base to harden, not a rewrite. **Phase 0 exists to make the default
`trishul scan .` real, safe, and honest before anything is built on top of it.**

---

## 3. Who we are building for

| Persona | What they want | How they find us | What they will not tolerate |
|---|---|---|---|
| **Solo builder** shipping with Cursor, Claude Code, Lovable, Bolt, v0 | "Is my app safe to launch?" in one command, in plain English, with a fix they can paste back into their agent | Reddit, X, Hacker News, YouTube, their agent suggesting it | Installing Docker and Redis. Jargon. 400 low-severity lint findings. |
| **Startup engineer** on a team that adopted coding agents | A gate in CI and in the agent loop so AI-written PRs do not ship the usual mistakes | GitHub Marketplace, blog posts, colleagues | False positives that block merges. Slow scans. |
| **Security lead** at a company where AI now writes half the code | Evidence of which AI-written code was checked, and a policy they can enforce | The benchmark report, conference talks | Closed-source black boxes. No SARIF. |

Phases 0 to 2 are for the solo builder. The startup engineer is served from Phase 2. The security
lead is served by the benchmark and provenance work in Phases 2 and 4.

---

## 4. The landscape and our wedge

The category already exists and is filling up fast.

| Group | Examples | Strength | Gap we exploit |
|---|---|---|---|
| Hosted URL scanners | Vibe App Scanner, CheckVibe, VibeCheck, amihackable.dev | Zero install, non-technical friendly | Closed source; mostly probe the deployed app; cannot see source-only flaws; no agent loop |
| Small open-source scanners | vibe-audit, VibeGuard, ChakraView | Right positioning | Tens of regex patterns; no taint analysis, no dependency intelligence |
| Platforms | Aikido, Snyk, Semgrep | Depth, enterprise trust | Heavy; priced and designed for security teams; vibe coding is a feature, not the product |
| Agent-surface scanners | Snyk agent-scan (formerly mcp-scan), Cisco MCP Scanner, rulesentry | Cover MCP, skills, rules files | Do not scan the application code at all |
| Built-in platform checks | Lovable security scan, Supabase advisors | In the workflow | Single platform; check that features exist, not that they are correct |

**Our wedge:** nobody combines all four of these in one open-source binary.

1. Real static analysis depth (taint-capable engine plus the best existing scanners).
2. Rules written for the vibe stack: Next.js, Supabase, Firebase, Vercel, Stripe, Clerk, LLM SDKs.
3. Dependency intelligence aimed at hallucinated and malicious packages.
4. The agent's own attack surface: rules files, MCP configs, skills, hooks.

And then closes the loop by handing the fix back to the agent.

---

## 5. The Vibe Top 10

A named taxonomy is the most valuable asset in a new category. It gives every finding a stable ID,
gives journalists and other tools something to cite, and organises our rule writing. This is the
first draft; it should be validated against the benchmark corpus in Phase 4 and versioned yearly.

| ID | Name | Typical AI-generated form |
|---|---|---|
| **V01** | Secrets shipped to the client | Supabase service-role key in a React component; `NEXT_PUBLIC_` or `VITE_` prefix on a secret; API keys in the JS bundle or a committed `.env` |
| **V02** | Missing or client-only authorization | API routes and server actions with no session check; auth enforced only by hiding a button; IDOR on `/api/users/[id]` |
| **V03** | Open data layer | Supabase tables without RLS, or policies of `using (true)`; Firebase rules `allow read, write: if true`; public storage buckets |
| **V04** | Hallucinated and risky dependencies | Packages that do not exist, were registered last week, are one edit away from a popular name, or are flagged malicious |
| **V05** | String-built injection | SQL via template literals; `exec` with user input; SSRF through user-supplied URLs; `dangerouslySetInnerHTML` |
| **V06** | Placeholder security | `JWT_SECRET = "secret"`; `admin/admin`; `verify=False`; `cors({ origin: "*" })`; debug mode on; `// TODO: add auth` |
| **V07** | Unverified webhooks and payment logic | Stripe webhook without signature verification; price or plan trusted from the client |
| **V08** | Missing abuse controls | No rate limiting on auth or LLM endpoints; unbounded uploads; no input validation |
| **V09** | Unsafe LLM integration | User input concatenated into system prompts; model output passed to `eval`, SQL or HTML; provider keys called from the browser |
| **V10** | Poisoned agent context | Hidden Unicode in `.cursorrules`, `CLAUDE.md`, `AGENTS.md`; unpinned `npx -y` MCP servers; blanket agent permissions; secrets in MCP config |

Every rule we ship maps to one of these plus a CWE. Reports lead with the Vibe Top 10 view.

### AI Agent Supply-Chain Security (V10, deepened)

AI coding agents — Claude Code, Cursor, Codex, Copilot — now read your repo, check
out pull requests, follow repository instructions, install dependencies, and run
tools. That makes the repository itself an attack surface: a malicious PR can plant
instructions in `CLAUDE.md`, a code comment, a README, an MCP config, a CI workflow,
or an install hook to redirect the agent — override its instructions, induce
unauthorized tool calls, disclose credentials, add network destinations, weaken
sandboxing, or register an untrusted MCP server.

Trishul treats this as a seventh, first-class capability. It analyzes changed files
*and* relevant context, parses agent/MCP/CI configuration structurally, detects
prompt-injection and encoded/obfuscated instructions, and correlates
individually-innocent changes into a single evidence-backed **attack chain**:
untrusted entry point → agent consumption → requested action → trust boundary
crossed. Analysis is **passive by default** — Trishul never executes untrusted
instructions, hooks, install scripts, or MCP servers, and treats all scanned text as
data, never as instructions to its own analysis. Exposed via
`trishul agent-security scan .` and `trishul agent-security pr --base main`, and
folded into the normal scan pipeline without making an external LLM mandatory.

---

## 6. Product pillars

1. **Ten seconds to first finding.** One static binary. No server, no Redis, no Docker for the
   default path. `npx trishul` works on a fresh machine.
2. **Vibe-native detection.** Our own rule pack and stack analyzers for the Vibe Top 10, on top of
   the best open-source scanners.
3. **In the agent loop.** MCP server, editor hooks, and fix prompts, so the agent that wrote the
   bug fixes it before the human sees it.
4. **Signal over volume.** A default profile that shows only security findings worth acting on.
   Complexity, docstring and style tools are off unless asked for.
5. **Proof in public.** A reproducible benchmark of what each AI tool generates and what trishul
   catches, published on a schedule.

---

## 7. Phases

Phases are ordered by dependency, not by date. Each has an exit test that can be checked by a
stranger on a clean machine. The task-level breakdown — with checkboxes, `file:line` references and
per-task acceptance checks — lives in [`docs/IMPLEMENTATION-PLAN.md`](docs/IMPLEMENTATION-PLAN.md).

### Phase 0: Make the promise true & make it safe (v0.1)

Nothing else matters until a stranger can install Trishul, run `trishul scan .` on a real project,
get honest results, and have their files untouched. Phase 0 is the embedded in-process engine (no
Redis/server for the default path, server retained for CI/hosted), the non-negotiable safety fixes
(secret redaction, read-only guarantee, honest skipped-tool reporting), findings/SARIF
normalisation, scan profiles (security by default), green CI, and finishing the `armur → trishul`
rename.

**Exit test:** on clean macOS and Ubuntu, `trishul scan .` against `examples/vibe-coded-app`
finishes under 60 s, reports the planted findings, leaves the directory byte-identical, surfaces
any skipped tools, leaks no plaintext secret, and makes no network calls beyond opt-in tool/DB
updates.

### Phase 1: Reliable core + vibe-native detection (v0.2 to v0.3)

The moat. The six capabilities each get genuinely-wired, structured, tested adapters (reviving the
dead in-scope wrappers), a real taint-capable engine for source→sink evidence, and Trishul's own
analyzers and rule packs for the [Vibe Top 10](#5-the-vibe-top-10) — Supabase RLS, Firebase rules,
framework route/authorization inventory, hallucinated-dependency intelligence, and unsafe-LLM
patterns. Every detector ships with a vulnerable and a safe fixture.

**Exit test:** each Vibe Top 10 class fires on its vulnerable fixture and stays silent on its safe
fixture; scans are reproducible (same input → same fingerprints).

### Phase 2: In the agent loop (v0.4)

Where Trishul becomes part of how AI-written code is made: a shipped MCP server (scan, explain,
propose-and-verify-fix) for Claude Code / Cursor / Copilot / Codex, editor and pre-install hooks, a
prompt-injection guard for Trishul's own AI features, fix prompts, guard-rule generation, and the
agent-surface scanner (`CLAUDE.md`/`.cursorrules`/MCP-config change detection — treating those files
as untrusted data).

**Exit test:** in a recorded session, an agent writes a Supabase table without RLS, the hook fires,
the agent receives the finding, and the verify-loop confirms the fix — with no human typing.

### Phase 3: PR review & scanner breadth (v0.5)

A diff-aware PR gate that distinguishes newly-introduced findings from pre-existing ones (including
new findings surfaced by changed data-flow/config, not just changed lines), with SARIF and GitHub
annotations — plus broader, benchmarked tool coverage from the [expansion plan](#8-scanner-expansion-plan),
each addition pinned, normalised, fixtured and Vibe-Top-10-mapped.

**Exit test:** a PR introducing a vuln is flagged as *new* and a pre-existing one is not re-reported;
the README tool matrix is generated from code and CI fails if a listed tool has no passing fixture.

### Phase 4: Proof and distribution (v0.6 to v1.0)

Public, reproducible evidence: **VibeBench** (app prompts run through each major AI coding tool,
scanned, numbers published) as the precision/recall harness; reachability/exploitability triage with
VEX output; incremental/cached scans; the Marketplace Action; a web scan at trishul.dev; the
"Scanned by Trishul" badge; and a single editor extension.

**Exit test:** VibeBench recall above an agreed bar for every Vibe Top 10 class and the
false-positive rate on the safe corpus below an agreed bar (bars set from the first run).

### Phase 5: Runtime verification (after v1.0, demand-driven)

Out of scope for the current upgrade; the isolated sandbox/DAST/exploit code stays in-tree and
returns here only as *verification of static findings* — `trishul probe <url>` for owned apps
(ownership proof required), "confirmed exploitable" labelling, and an attack-path view on confirmed
findings.

### Later, demand-driven

Hosted dashboard and team features, policy enforcement, SBOM and compliance exports. These fund
the project; they do not define it.

---

## 8. Scanner expansion plan

### Fix or retire what we already wrap

| Tool | Action | Why |
|---|---|---|
| Semgrep `--config=auto` | Replace with a pinned rule set, evaluate Opengrep as the default engine | Offline, no metrics, licence-clean, cross-function taint |
| `trufflehog3` | Replace with TruffleHog (Go) or Kingfisher | Wrong project is installed today |
| tfsec | Retire in favour of Trivy config scanning | Upstream folded it into Trivy |
| Terrascan | Verify upstream status, likely retire | Not actively maintained |
| golint | Retire | Deprecated upstream for years |
| gocyclo, radon, pydocstyle, pylint, jscpd | Move to `--profile quality` | Noise for the default audience |
| Slither, Mythril | Keep, move to an opt-in `web3` profile | Not the vibe stack |
| Gitleaks, Grype, govulncheck, npm and pip audit | Wire into the pipeline | Wrappers already exist |

### Add

Ordered by value to the vibe stack. Tier 1 lands in Phases 1 and 2; the rest in Phase 3.

| Tier | Tool | Category | What it gives us |
|---|---|---|---|
| 1 | [Opengrep](https://github.com/opengrep/opengrep) | SAST engine | Semgrep-compatible rules with cross-function taint; the engine for our own rule pack |
| 1 | [Gitleaks](https://github.com/gitleaks/gitleaks) | Secrets | Fast, single binary, git history |
| 1 | [Kingfisher](https://github.com/mongodb/kingfisher) or [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Secrets | Live validation: "this key works" is the finding people act on |
| 1 | [OSV-Scanner](https://github.com/google/osv-scanner) v2 | SCA | Lockfile scanning, malicious-package advisories, guided remediation |
| 1 | [GuardDog](https://github.com/DataDog/guarddog) | Supply chain | Heuristics for malicious npm, PyPI and Go packages |
| 1 | [Snyk agent-scan](https://github.com/snyk/agent-scan) | Agent surface | MCP, skills and agent config scanning, alongside our own rules-file checks |
| 1 | ESLint security stack | JS/TS SAST | `eslint-plugin-security`, `no-unsanitized`, `eslint-plugin-react` danger rules, `@next/eslint-plugin-next` |
| 2 | [ast-grep](https://github.com/ast-grep/ast-grep) | Structural rules | Very fast tree-sitter matching for framework-shape rules |
| 2 | [Ruff](https://github.com/astral-sh/ruff) (`S` rules) | Python SAST | Bandit's checks at a fraction of the runtime |
| 2 | [njsscan](https://github.com/ajinabraham/njsscan) | Node SAST | Node-specific sinks Semgrep's generic rules miss |
| 2 | [zizmor](https://github.com/zizmorcore/zizmor), [actionlint](https://github.com/rhysd/actionlint) | CI | AI-written GitHub workflows: injection, broad permissions, unpinned actions |
| 2 | [Squawk](https://github.com/sbdchd/squawk) | Database | Postgres migration linting next to our RLS analyzer |
| 2 | [Splinter](https://github.com/supabase/splinter) | Database | Supabase's own lints, in live mode |
| 2 | [Syft](https://github.com/anchore/syft) | SBOM | One SBOM feeding Grype, OSV and the dependency checks |
| 2 | [retire.js](https://github.com/RetireJS/retire.js) | Frontend SCA | Vendored and CDN-loaded libraries that no lockfile lists |
| 2 | [knip](https://github.com/webpro-nl/knip) | Dependencies | Unused packages and exports |
| 3 | [mobsfscan](https://github.com/MobSF/mobsfscan) | Mobile | Expo and React Native apps |
| 3 | [Vacuum](https://github.com/daveshanley/vacuum) or Spectral with the OWASP rules | API | OpenAPI specs |
| 3 | [Dockle](https://github.com/goodwithtech/dockle), [Kubescape](https://github.com/kubescape/kubescape) | Containers, K8s | Image and cluster posture |
| 3 | [poutine](https://github.com/boostsecurityio/poutine) | CI | Build-pipeline supply chain |
| 3 | [ShellCheck](https://github.com/koalaman/shellcheck) | Shell | Advertised already; actually add it |
| 3 | [Bearer](https://github.com/Bearer/bearer) | Data-flow SAST | Sensitive-data flows; licence needs review before bundling |
| 3 | [promptfoo](https://github.com/promptfoo/promptfoo), [garak](https://github.com/NVIDIA/garak) | LLM red-teaming | Dynamic testing of the app's own LLM features; belongs with Phase 5 |

### Build ourselves

No existing open-source tool does these well, which is why they are the moat:

- Supabase migration and policy analyzer
- Firebase rules analyzer
- Next.js, Express, FastAPI route and authorization inventory
- Client-exposure analyzer for secrets
- Hallucinated-dependency checker
- Rules-file and agent-config scanner
- The Vibe Top 10 rule pack

---

## 9. What we are cutting

The old plan had 59 sprints. These are removed from the roadmap and from the README until there
is demand:

- Distributed workers, multi-tenant API, RBAC and SSO
- Binary analysis, fuzzing, threat-model generation, test generation
- PCI-DSS, HIPAA and NIST compliance mapping (OWASP and CWE stay)
- Rules marketplace, gamification, Slack and Teams bots
- Per-language breadth for its own sake: PHP, Ruby, C/C++, C#, Swift, Java stay supported where
  wrappers work, but get no new investment. **TypeScript, JavaScript and Python get all of it**,
  with Go next.
- Exploit simulation and attack paths as headline features. They return in Phase 5 as
  verification of static findings.

The code for these stays in the tree for now. It leaves the marketing.

---

## 10. Go-to-market

**One sentence everywhere:** "Find vulnerabilities in Cursor, Claude Code, Copilot and Windsurf
generated applications before they reach production."

**Launch sequence**
1. Phase 0 done: quiet release, fix what breaks for the first fifty users.
2. Phase 1 done: public launch. Show HN, r/cursor, r/ClaudeAI, r/vibecoding, X. The demo is a
   thirty-second recording: generate an app, scan it, paste the fix prompt, rescan clean.
3. Phase 2 done: second launch aimed at agent users: "trishul inside Claude Code and Cursor".
4. Phase 4: the benchmark report is the third launch and the one that gets press.

**Compounding loops**
- The Vibe Top 10 as a standalone page others link to.
- The badge on scanned repos.
- Agents recommending trishul because `guard` put it in the repo's rules file.
- A rule-contribution path simple enough that a finding on X becomes a merged rule in a day.
- One "we scanned N apps built with X" post per major AI tool.

**What to measure**
- Time from install to first finding on a clean machine
- Weekly scans (opt-in, anonymous) and weekly active repos in CI
- Benchmark recall and false-positive rate per Vibe Top 10 class
- Stars and contributors as a lagging signal only

---

## 11. Risks

| Risk | Why it matters | Mitigation |
|---|---|---|
| **Name collision** | `trishul` on PyPI belongs to someone else; several "vibe" scanners already exist | Decide the package names now; reserve npm, the VS Code publisher and the domain; never document an install path we do not own |
| **Rule licensing** | Semgrep's registry rules carry a licence that restricts use in competing products | Own rule pack plus permissively licensed community rules; engine via Opengrep |
| **Bundled tool licences** | Some candidates (Bearer, CodeQL) restrict redistribution or commercial use | Licence review is part of the definition of done for every tool added |
| **Crowded category** | New scanners appear monthly | Depth that regex scanners cannot copy quickly: stack analyzers, taint rules, benchmark, agent loop |
| **Platforms absorb the category** | Cursor, Lovable, GitHub ship built-in checks | Be the cross-tool, open, local option they cannot be; integrate rather than compete |
| **False positives** | One noisy launch loses the solo builder for good | Safe fixtures for every rule; the default profile is security-only; benchmark gates releases |
| **Probing third-party apps** | Active checks on apps the user does not own are a legal problem | Ownership proof before any active probe; passive checks only otherwise |
| **Credibility** | The previous README claimed features and install paths that did not work | Status table in the README; nothing is advertised before its exit test passes |

---

## 12. Open decisions

These need an owner's call before Phase 0 finishes.

1. **Package names.** PyPI `trishul` is taken. Options: drop pip entirely (npm, brew and curl
   cover the audience), or publish as `trishul-cli`. Recommendation: drop pip.
2. **Default engine.** Opengrep versus Semgrep CE. Recommendation: Opengrep, with Semgrep as a
   fallback if already installed.
3. **Module and repo naming.** The Go module is still `github.com/Armur-Ai/Trishul` and the working folder
   `Armur-Code-Scanner`. Recommendation: rename the module to `github.com/Armur-Ai/trishul` as
   part of the single-binary merge.
4. **Versioning.** The CLI prints `v0.1.0` and nothing has been released. Recommendation: tag
   `v0.1.0` at the Phase 0 exit test and stay below 1.0 until the benchmark gates pass.
5. **Telemetry.** Opt-in anonymous scan counts are the only way to measure the funnel.
   Recommendation: opt-in, documented, off by default.
6. **Hosted scan.** Whether trishul.dev offers a free web scan in Phase 4 or earlier. It is the
   strongest top-of-funnel move and also an operating cost. The domain currently returns 503.

---

## 13. Immediate priorities

The ordered, PR-sized task list has moved to **Phase 0** of
[`docs/IMPLEMENTATION-PLAN.md`](docs/IMPLEMENTATION-PLAN.md). The first few, in order:

1. Redact secrets everywhere + canary regression test (the plaintext-leak P0).
2. Guarantee read-only scans (remove `RemoveNonRelevantFiles`; add the "target untouched" test).
3. Honest scanner status (version/existence detection; surface skipped tools; kill soft timeouts).
4. Fix `trishul scan .` end-to-end via the embedded in-process engine.
5. Normalise findings + SARIF (stable fingerprints, all categories, `partialFingerprints`).
6. Green CI; remove the committed binary; finish the `armur → trishul` rename.

See the implementation plan for the full breakdown with acceptance checks.
