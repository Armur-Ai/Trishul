# Quick Start

Get your first security scan running from source.

> **Pre-release.** There are no published packages yet (Homebrew, npm, and an
> install script are planned but not live), so you build Trishul from source.
> You need Docker and Go 1.25 or newer.

## Install (from source)

```bash
git clone https://github.com/Armur-Ai/trishul
cd trishul

# 1. Start the scan engine (first build takes a few minutes)
docker compose up -d --build

# 2. Build the CLI
(cd cli && go build -o ../bin/trishul .)
```

## Scan Your Project

```bash
# Scan a single file
./bin/trishul scan examples/vibe-coded-app/server.js

# Scan a remote repository (language required for repos)
./bin/trishul scan https://github.com/you/your-app -l js
```

Languages for `-l`: `go`, `py`, `js`, `rust`, `java`, `ruby`, `php`, `c`, `iac`,
`sol`.

> Scanning a local directory straight from the CLI is **not yet wired** — scan a
> single file or a repository URL for now.

Useful flags:

```bash
./bin/trishul scan <target> --advanced            # deep pass: deps, IaC, duplication, dead code
./bin/trishul scan <target> --output json         # machine-readable results
./bin/trishul scan <target> --format sarif        # SARIF 2.1.0 output
./bin/trishul scan <target> --fail-on-severity high  # non-zero exit for CI
./bin/trishul scan <target> --profile quality     # also complexity/style/dead-code
./bin/trishul scan <target> --profile web3        # also smart-contract tools
```

## What Happens

1. Trishul detects the language(s) in your target.
2. Runs security tools appropriate for that language, plus the built-in
   analyzers (Supabase RLS, client-secret exposure, and **agent-security**) that
   run on every scan.
3. Deduplicates and normalizes findings, mapping them to CWEs.
4. Shows results in a severity-sorted summary.

By default scans use the **security** profile (security findings only). Every
scan is **read-only** — it never modifies the target — and any
skipped/uninstalled tool is reported honestly rather than hidden.

## Next Steps

- [Configure your project](../configuration/trishul-yml.md) with `.trishul.yml`
- Learn about [AI Agent Supply-Chain Security](../agent-security.md), which runs
  on every scan
- Review the [capabilities and supported tools](../tools/supported-tools.md)
- [Add to CI/CD](../ci/github-actions.md) for automated scanning
