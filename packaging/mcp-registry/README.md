# Trishul — MCP server listing copy

Reusable listing copy for MCP directories (Smithery, Glama, mcp.so, PulseMCP,
and the official MCP Registry). Trishul is **local-first**: the MCP server runs
on the user's own machine via `trishul mcp` — nothing is hosted by us, and no
code or findings ever leave the box.

Source of truth for machine-readable metadata:

- `server.json` (repo root) — official MCP Registry schema.
- `packaging/mcp-registry/smithery.yaml` — Smithery manifest.

---

## Short description

> Local-first security scanner (SAST, SCA, secrets, IaC, and AI-agent/MCP
> supply-chain checks) exposed as MCP tools. Everything runs on your machine;
> no code or findings leave your box.

## Install (one-liner)

```bash
trishul mcp setup claude
```

(also: `trishul mcp setup cursor`, `windsurf`, or `vscode`.)

First get the `trishul` binary, if you don't have it:

```bash
brew install armur-ai/tap/trishul          # Homebrew (macOS / Linux)
npx trishul-cli --version                   # npm
go install github.com/Armur-Ai/Trishul/cli@latest   # Go
```

Then `trishul mcp setup claude` writes the `trishul` MCP server entry into the
client's config (idempotent, with a `.bak` backup). Or run the server directly:
`trishul mcp`.

## Tools

| Tool | What it does |
| --- | --- |
| `trishul_scan_path` | Scan a local file or directory for security vulnerabilities. |
| `trishul_scan_code` | Scan a code snippet for security vulnerabilities. |
| `trishul_audit_mcp_config` | Audit MCP/agent client config (unpinned servers, plaintext tokens, overbroad permissions, insecure remotes). Read-only. |
| `trishul_suggest_fix` | Suggest a deterministic, local fix for a finding (returns a patch; does not write files). |
| `trishul_scan_diff` | Scan a git checkout and report only findings introduced vs. a base ref (the PR-gate diff). Read-only. |
| `trishul_explain_finding` | Explain a security finding in plain English. |
| `trishul_check_dependency` | Check whether a package version has known vulnerabilities. |
| `trishul_get_history` | Return recent scan history. |

No secrets or API keys are required; scanning is fully local. (An optional
`TRISHUL_*` AI key only enriches `trishul_explain_finding` / `trishul_suggest_fix`.)

---

## Versioning

The listing version must track the Trishul release so directories never point at
a stale description.

- `server.json` `version` and each `packages[].version` are kept equal to the
  **`actionVersion`** constant in `cli/cmd/init_github.go` (the version new
  releases pin to), with the leading `v` stripped — e.g. `v0.2.0` → `0.2.0`.
- `smithery.yaml` `version` is kept equal to the same value.
- **Enforced offline** by `internal/mcpmeta` (`go test ./...`): the test parses
  `server.json`, asserts required fields + semver format, and fails if its
  version does not match `actionVersion`. CI also re-runs it in
  `.github/workflows/mcp-registry-check.yml`.

**To cut a release:** bump `actionVersion` in `cli/cmd/init_github.go`, then set
the same version (minus `v`) in `server.json` (top-level + both package entries)
and `smithery.yaml`. The `mcpmeta` test will fail until they match, so drift is
caught before merge.

---

## Submission checklist — OWNER / D-HUMAN steps (publishing is gated)

> These artifacts are **prepared only**. Do **not** publish or submit from CI or
> from an agent. Each target below is a human/owner action, to be done once the
> v0.2.0 packages (`trishul-cli` on npm + PyPI, Homebrew tap) are actually
> published.

- [ ] **(D-HUMAN) Official MCP Registry** — install the `mcp-publisher` CLI,
      authenticate as `io.github.armur-ai`, and `mcp-publisher publish` the
      repo-root `server.json`. Requires GitHub ownership of `Armur-Ai`.
- [ ] **(D-HUMAN) Smithery** — submit/claim `io.github.armur-ai/trishul` at
      smithery.ai using `packaging/mcp-registry/smithery.yaml`.
- [ ] **(D-HUMAN) Glama** — list at glama.ai/mcp; uses this README copy + repo.
- [ ] **(D-HUMAN) mcp.so** — submit at mcp.so using this README copy + repo.
- [ ] **(D-HUMAN) PulseMCP** — submit at pulsemcp.com using this README copy.
- [ ] **(D-HUMAN) Pre-reqs before any of the above:** publish `trishul-cli`
      to npm and PyPI at the matching version, and push the Homebrew cask to
      `Armur-Ai/homebrew-tap`, so install instructions resolve.

Nothing in this directory contacts a registry or publishes anything.
