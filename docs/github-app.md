# Trishul GitHub App

Install once on an organization and every pull request in every selected repository gets:

- a **Trishul** check run with inline annotations on the changed code;
- one PR comment, posted only when the PR introduces an issue and then edited in place on each push;
- a README badge for the default branch.

No workflow YAML is needed. Install: **https://armur.ai/trishul-app/**

## Behaviour

| | |
|---|---|
| What is reported | Findings present in the PR head but not in the PR's merge base. Test/fixture code is ignored except for secrets and agent-security findings. Findings below `medium`, and findings in `.trishul-baseline.json`, are not reported. |
| Check conclusion | `success` when nothing is new, `neutral` when there are new findings (non-blocking), `failure` only when blocking is enabled. |
| Blocking | Opt in with `.trishul.yml` on the **base** branch (a PR can't switch off its own gate): `fail-on-findings: true` plus `severity-threshold: high`. Then make the *Trishul* check required in branch protection. |
| Re-run | "Re-run" on the check re-scans. New pushes supersede queued scans of older commits. |

## Permissions and data handling

Requested permissions: **Checks: write**, **Pull requests: write** (for the comment), **Contents: read**, **Metadata: read**.

For each scan the app downloads the PR head and merge-base tarballs into a temporary directory. It extracts regular files only (no symlinks, size-capped) and runs the read-only built-in analyzers in-process, never executing repository code. It then deletes the directory. It stores per-repo badge state (grade and severity counts) and an event log of scan counts for adoption metrics. It does not store source code or finding text.

## Operating it (Armur)

- Code: `cmd/trishul-app`, `internal/ghapp`, `internal/prgate`. Deploy with `deploy/trishul-app/deploy.sh` (systemd + nginx on the armur.ai VM, `/trishul-app/` → `127.0.0.1:4610`).
- Secrets live only on the VM in `/etc/trishul-app/` (`key.pem`, `webhook-secret`, `stats-token`, `env`).
- Health: `https://armur.ai/trishul-app/healthz`. Adoption and retention: `curl -H "Authorization: Bearer $(cat stats-token)" https://armur.ai/trishul-app/stats` reports installs, active repos over 7 and 30 days, comments, and 30-day retention.
- Logs: `journalctl -u trishul-app`.
