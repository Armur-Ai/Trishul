# Changelog

All notable changes to Trishul are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Vibe Top 10 — built-in analyzers (new)
- New `vibe_security` finding category and five built-in, dependency-free, read-only analyzers that run on every scan and emit to SARIF/CLI:
  - **placeholder-security** (V06) — hardcoded placeholder secrets (redacted), default credentials, disabled TLS verification, wildcard CORS + credentials, debug-on, security TODOs (`VIBE-PLACEHOLDER-001..006`).
  - **webhook-verification** (V07) — provider webhooks (Stripe/Svix/Clerk/GitHub/Shopify/PayPal) without signature verification, and `amount`/`price`/`plan`/`role` trusted from the request body (`VIBE-WEBHOOK-001..002`).
  - **abuse-controls** (V08) — auth/LLM routes with no rate limiting (project-wide suppression if a limiter exists), unbounded uploads, unvalidated mutating routes (`VIBE-ABUSE-001..003`).
  - **llm-integration** (V09) — untrusted input concatenated into prompts, model output into `eval`/exec/SQL/`innerHTML`, provider keys in client code; bounded taint propagation, key values never emitted (`VIBE-LLM-001..003`).
  - **dependency-provenance** (V04) — non-registry dependency sources, unpinned floating specs without a lockfile, and `overrides` repointing to non-registry sources (`VIBE-DEP-001..003`).
- **Firebase/Firestore/Storage rules** analyzer (V03 complement) — world-readable/writable rules, auth-only (no-ownership) rules, public buckets (`FIREBASE-00x` → `infra_security`).
- All Vibe analyzers are read-only, deterministic, and redact secrets; see [docs/vibe-top-10.md](docs/vibe-top-10.md).

### AI Agent Supply-Chain Security (new capability, in progress)
- New `internal/agentsec` subsystem protecting developers whose AI coding agents (Claude Code, Cursor, Codex, Copilot) review/checkout PRs, read repo instructions, install deps, and run tools — from malicious instructions and execution paths planted in untrusted PRs/repos.
- Seven self-registering, passive, read-only components (treat scanned text as data; never execute it): **agent-instruction analysis**, **prompt-injection** (heuristic; capped at MEDIUM), **command/execution-path** (install/CI hooks, curl|sh, secret exfil), **MCP server & tool trust** (unpinned runners, remote-code servers, embedded secrets — redacted), **permission/sandbox config** (allow-all, bypass modes, `--dangerously-*`), **encoded/obfuscation** (invisible/bidi Unicode, base64/hex decoding to instructions, hidden HTML comments), and **cross-file attack-chain correlation** (`AGENT-CHAIN-001` — raises corroborated signals to HIGH, e2e-tested).
- Findings carry the **trust boundary** crossed, the affected agent workflow, confidence + limitations, and remediation; wired into every scan and emitted to SARIF; rendered in the CLI. Never claims an agent is compromised merely because suspicious text exists.

### Phase 0: Safety & honesty hardening (in progress)
- **Secrets never leak in plaintext** — new `internal/redact` package; TruffleHog findings emit a masked preview + non-reversible fingerprint instead of the raw value, closing the JSON-API / Redis / webhook leak. Canary regression test added.
- **Read-only scans** — `SafeRemoveAll` / `IsManagedPath` guards; file pruning no-ops on any non-managed (user) path; byte-identical invariant test guarantees a scan never modifies the target.
- **Honest scanner status** — `RunToolCommand` helper adds an availability check and a timeout that actually kills the process; known-missing tools are reported as skipped (never as a clean result) and surfaced in the CLI; structured `ToolOutcome` enum.
- **Scanner adapters** (~47) routed through the timeout/availability helpers, preserving each tool's output semantics.
- **SARIF** — stable `partialFingerprints` (cross-run tracking) + deterministic rule ordering.
- **Scope** — smart-contract tools (Slither/Mythril) gated behind an opt-in `TRISHUL_PROFILE=web3`.
- **Fixes** — BatchScan scan-type mismatch; CI aligned to Go 1.25 (was red); removed a committed 14 MB binary; corrected DAST/exploit-simulation overclaims in packaging and docs; `armur` → `trishul` rename across MCP tools, the Action, pre-commit hooks, and docs.
- **Normalization** — one canonical severity mapper (no divergent copy); a **stable, line-insensitive finding fingerprint** with an aligned dedup key; SARIF now emits **all categories** (security, redacted secrets, SCA, IaC) with stable per-rule ids and `partialFingerprints`.
- **Profiles** — `--profile security|quality|web3|all`; the default `security` profile omits code-quality tools and keeps smart-contract tools opt-in.
- **Embedded engine (foundation)** — `engine.ScanLocal` runs a scan in-process (no server/Redis, read-only); the MCP server now uses it. (CLI `scan .` via a module-merge is a separate step.)
- **Tests** — parse-level coverage for the six previously-untested adapters (gitleaks, govulncheck, grype, sbom, sca, terrascan).
- **Supabase RLS analyzer** (Vibe Top 10 V03) — a built-in, dependency-free, read-only detector for open-data-layer misconfigurations (missing row-level security, `using (true)` policies, anon write grants, `security definer` without `search_path`, public storage buckets); runs on every scan.
- **Client-exposed-secret analyzer** (Vibe Top 10 V01) — a built-in, read-only detector for secrets shipped to the client (`NEXT_PUBLIC_`/`VITE_`/etc. values, committed `.env` secrets, service-role JWTs / private keys in client-side files); emits only redacted previews, never a raw value (enforced by an end-to-end no-leak test).
- The local-scan path now **surfaces the built-in analyzers' findings** (infra + secrets), and the in-process `engine.ScanLocal` is e2e-tested against both analyzers.

### Phase 1: Foundation (Sprints 1-4)
- Test suite, error propagation, input validation, structured logging, API authentication
- Parallel tool execution, diff scanning, plugin system, project config, Docker images
- SARIF output, GitHub Actions, pre-commit hooks, webhooks, GitLab CI
- Language expansion: Rust, Java/Kotlin, Ruby, PHP, C/C++, IaC (Terraform, Docker, K8s), Solidity

### Phase 2: Core Product (Sprints 5-14)
- `trishul serve` embedded server with auto-start, SSE progress streaming, severity summary card
- SQLite scan history, `trishul init`, `trishul doctor`, shell completions, `--watch` mode
- `trishul run` — multi-step wizard, live Bubbletea TUI dashboard, interactive results browser
- Unified `Finding` type with severity normalization, deduplication, and fingerprinting
- Smart scanning — auto-detect language, `.trishul.yml` project config, diff scanning
- Lipgloss-styled display, HTML/CSV reports, embedded miniredis for zero-infrastructure mode
- CI/CD workflows, goreleaser, issue templates, SECURITY.md, `trishul version`
- Documentation site skeleton, CLI reference, config reference, tool reference
- Multi-ecosystem SCA: npm-audit, pip-audit, composer-audit, ecosystem detection

### Phase 3: The Agent Edge (Sprints 15-21)
- **Rebrand** to "Trishul — Personal Security Agent" with agent pipeline orchestrator
- **AI Intelligence Layer**: Claude API + Ollama providers, tech stack detection, `trishul explain`, `trishul fix`
- **Sandboxed DAST**: Docker isolation, auto-Dockerfile generation, health detection, passive checks, Nuclei integration
- **Exploit Simulation**: PoC generator (SQLi, XSS, cmd injection, path traversal, SSRF), safe sandbox runner
- **Attack Path Analysis**: Graph construction, 8 chain rules, scoring, Mermaid visualization
- **PR Security Agent**: `trishul review <pr-url>`, review pipeline, GitHub integration, AI narrative
- **MCP Server**: 5 MCP tools for Claude Code/Cursor/Windsurf integration

### Phase 4: Distribution & Community (Sprints 22-32)
- npm package scaffold, universal install script (`curl | sh`), GitHub Action (action.yml)
- VS Code extension scaffold, CI templates (GitLab, CircleCI, Jenkins)
- `trishul quickstart` interactive guide, security posture score (0-100, A-F grading)
- Community ecosystem: template registry, exploit templates, sandbox profiles, fix recipes, attack chains

### Phase 5: Scanner Breadth (Sprints 33-43)
- Gitleaks deep secrets scanning, OpenAPI spec security analysis
- OWASP Top 10 2021 compliance mapping with CWE lookup table
- SBOM generation (CycloneDX/SPDX via cdxgen/trivy), supply chain checks
- C#/.NET (SecurityCodeScan, Roslynator), Swift/Shell (SwiftLint, ShellCheck)
- terrascan, kubesec (IaC deep), Grype and Trivy image scanning (containers)
- govulncheck with call-graph reachability analysis

### Phase 6: Advanced Capabilities (Sprints 44-55)
- Health/readiness endpoints, SSE event registry with ProgressReporter interface
- Typed API responses, batch scanning, X-Request-ID correlation middleware
- Rules marketplace registry (fetch, install, search, list)
- Go/Python/JS fuzzing integration, PII detection, cryptographic health checker
- Binary security (checksec, string scan), threat modeling with route detection + Mermaid DFD
- Dependency update automation, network config security, security test generation

### Phase 7: Scale & Intelligence (Sprints 56-59)
- File-level scan caching, monorepo service detection
- SLA tracking, security debt estimation, never-allow governance rules
- CISA KEV enrichment, EPSS exploit prediction scoring
- OWASP LLM Top 10 scanner (prompt injection, insecure output, excessive agency)
