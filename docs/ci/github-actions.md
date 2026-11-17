# GitHub Actions Integration

> **Pre-release note.** A published GitHub Action and install script are planned
> but not live yet, so these templates build Trishul from source. The SARIF
> upload flow below is the recommended way to surface findings — including AI
> agent supply-chain findings, which are emitted to SARIF like every other
> category.

## Quick Setup

Add this workflow to `.github/workflows/trishul.yml`:

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  trishul-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'

      # Pre-release: build from source until a packaged Action/binary ships.
      - name: Build Trishul from source
        run: |
          git clone https://github.com/Armur-Ai/trishul /tmp/trishul
          (cd /tmp/trishul && docker compose up -d --build)
          (cd /tmp/trishul/cli && go build -o /usr/local/bin/trishul .)

      - name: Run scan
        run: trishul scan https://github.com/${{ github.repository }} -l js --format sarif --output results.sarif --fail-on-severity high

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Fail on Severity

Use `--fail-on-severity` to fail the build when findings exceed a threshold:

```yaml
- run: trishul scan <target> --fail-on-severity high
```

Options: `critical`, `high`, `medium`, `low`

## Advanced: Deep Scan

Add `--advanced` for the deep pass (dependencies, IaC, duplication, dead code):

```yaml
- name: Deep scan
  run: trishul scan <target> --advanced --format sarif --output results.sarif
```

> Diff-only PR scanning and report generation in CI are planned; today a scan
> targets a single file or a repository URL.
