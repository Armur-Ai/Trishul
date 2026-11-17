# Capabilities & Supported Tools

Trishul is a local-first, read-only security scanner for AI-generated code. It
orchestrates a curated set of established open-source tools, adds its own
built-in analyzers, normalizes and deduplicates the results, and returns one
report. Tool availability is reported **honestly** at scan time — an uninstalled
or failed scanner is reported as skipped, never hidden, and never fails the scan.

## Capabilities

Trishul covers six analysis capabilities plus the flagship agent-security
subsystem:

| Capability | What it does |
|------------|--------------|
| **SAST** | Static analysis for vulnerable code patterns (injection, unsafe APIs, crypto, etc.) across every supported language. |
| **SCA** | Software-composition analysis: dependencies checked against known-vulnerability databases (CVE/OSV). |
| **Secrets** | Detection of leaked credentials and API keys, reported redacted (no plaintext in output, storage, webhooks, or reports). |
| **IaC** | Infrastructure-as-code policy and misconfiguration checks (Docker, Terraform, Kubernetes). |
| **Taint** | Data-flow tracing from untrusted sources to dangerous sinks. |
| **PR review** | Review of a pull request's changes (implemented as a package; not yet wired to the CLI). |
| **Agent supply-chain security** | The flagship subsystem that detects attacks aimed at the AI coding agent itself. See **[AI Agent Supply-Chain Security](../agent-security.md)**. |

All capabilities run **read-only**: a scan never modifies or deletes the target
tree.

## Scan profiles

A profile selects which tools run. The default is **security**.

| Profile | Runs |
|---------|------|
| `security` *(default)* | Security findings only — no complexity/style noise. |
| `quality` | Also runs complexity, style, and dead-code tools. |
| `web3` | Also runs smart-contract tools (Slither, Mythril). |
| `all` | Everything. |

The built-in, dependency-free analyzers — Supabase RLS, client-secret exposure,
and **agent-security** — run on every scan regardless of profile.

## Output formats

Results are available as CLI (human-readable), JSON (machine-readable), and
**SARIF 2.1.0**. SARIF output covers **all categories** — SAST, SCA, IaC,
redacted secrets, and agent supply-chain findings — with stable
`partialFingerprints` so findings deduplicate across runs. See
[GitHub Actions integration](../ci/github-actions.md) for uploading SARIF to code
scanning.

## Language Coverage

| Language | SAST | SCA | Secrets | Quality |
|----------|------|-----|---------|---------|
| **Go** | semgrep, gosec, govet, staticcheck | osv-scanner, trivy | trufflehog | gocyclo, golint |
| **Python** | semgrep, bandit | osv-scanner, trivy | trufflehog | pylint, radon, pydocstyle |
| **JavaScript/TS** | semgrep, eslint | osv-scanner, trivy | trufflehog | jscpd |
| **Rust** | semgrep, clippy | cargo-audit, cargo-geiger | trufflehog | — |
| **Java/Kotlin** | semgrep, spotbugs, pmd | dependency-check | trufflehog | — |
| **Ruby** | semgrep, brakeman | bundler-audit | trufflehog | — |
| **PHP** | semgrep, phpcs, psalm | — | trufflehog | — |
| **C/C++** | semgrep, cppcheck, flawfinder | — | trufflehog | — |
| **Solidity** | semgrep, slither, mythril | — | — | — |
| **IaC** | semgrep, checkov | — | — | hadolint, tfsec, kics, kube-linter, kube-score |

## Advanced Scan Tools (all languages)

| Tool | Category | Description |
|------|----------|-------------|
| jscpd | Duplicate code | Detects copy-pasted code blocks |
| checkov | IaC security | Infrastructure-as-code policy checks |
| trufflehog | Secrets | Finds leaked credentials and API keys |
| trivy | SCA + vulnerabilities | Scans dependencies for known CVEs |
| osv-scanner | SCA | Queries the OSV vulnerability database |

## Built-in analyzers (no external tool required)

These ship with Trishul and run without any external binary on `PATH`:

| Analyzer | Detects |
|----------|---------|
| Supabase RLS | Missing row-level security, `using (true)`, public buckets, unsafe `security definer` |
| Client-secret exposure | Secrets shipped to the client bundle (redacted) |
| Agent-security | AI agent supply-chain risks — see [agent-security.md](../agent-security.md) |

> **Honest tool status.** The Docker engine ships the JavaScript, Python, and Go
> scanners plus Trivy, OSV-Scanner, and Checkov. TruffleHog and the scanners for
> other languages run when their binary is on the engine's `PATH`; a missing tool
> is skipped and reported as such, never silently dropped and never a scan
> failure.
