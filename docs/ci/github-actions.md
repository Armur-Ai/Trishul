# GitHub Actions: the Trishul PR gate

The Trishul Action runs `trishul-ci`, a hermetic build of Trishul's built-in analyzers. It needs no server, no Redis and no external tools, and it never executes repository code. On a pull request it scans the PR and its base and reports **only the findings the PR introduces**.

## Quick setup

```bash
trishul init github --pr     # writes .github/workflows/trishul.yml and opens a PR
```

or add it by hand:

```yaml
name: Trishul
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
  pull-requests: write    # one PR comment, edited in place
  security-events: write  # SARIF upload to code scanning
jobs:
  trishul:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Armur-Ai/Trishul@v0.2.0
```

A typical scan takes a few seconds.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `fail-on` | *(empty)* | Fail the job when the PR introduces findings at or above this severity. Empty = never fail. Start empty, then set `high` once the team trusts it. |
| `min-severity` | `medium` | Only report findings at or above this severity. |
| `comment` | `auto` | `auto` comments only when there are new findings, then keeps that comment up to date (so a fixed PR flips to "all clear"). `always` or `never` are also accepted. |
| `upload-sarif` | `true` | Upload SARIF to code scanning. Skipped automatically when the token can't (e.g. fork PRs). |
| `baseline` | `.trishul-baseline.json` | Accepted findings that are never reported. |
| `include-tests` | `false` | Also report findings in test/fixture code. Secrets and agent-security findings are always reported. |
| `version` | action ref | `trishul-ci` release to use. |

Outputs: `new-count`, `critical-count`, `high-count`, `failed`, `sarif-path`.

## Supply-chain posture

The Action never runs `curl | sh`. When pinned to a release tag it downloads that release's `trishul-ci` archive and **verifies its sha256** against the release `checksums.txt` before running it. Pinned to a branch or SHA, it builds `trishul-ci` from the action's own source at exactly that ref, which needs `actions/setup-go`. For maximum assurance, pin to a full commit SHA.

## Adopting on an existing repo

PR scans already ignore pre-existing findings. To also keep them out of push scans and the Security tab, accept today's state as a baseline:

```bash
go install github.com/Armur-Ai/Trishul/cmd/trishul-ci@latest
trishul-ci --write-baseline .
git add .trishul-baseline.json && git commit -m "chore: trishul baseline"
```

The baseline is plain JSON (rule, path, message, fingerprint), so reviewers can see exactly what was accepted. Fingerprints don't include line numbers, so unrelated edits don't resurrect findings.

## Excluding paths

`.trishul.yml`:

```yaml
exclude:
  - vendor/**
  - "**/*.min.js"
```

## Running locally

```bash
trishul-ci --base origin/main .          # what would the PR gate say?
trishul-ci --sarif out.sarif --json out.json .
```

Exit codes: `0` pass, `1` gate failed (`--fail-on`), `2` error.
