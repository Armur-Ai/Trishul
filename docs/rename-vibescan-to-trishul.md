# Rename: VibeScan → Trishul

> Migration record for evolving the VibeScan product into **Trishul — Code
> Security & Quality**. Per the Armur six-product specification §12. This run
> performs the **identity/branding rename** and compatibility wiring; it does
> **not** implement new SAST/secrets/dependency analyzers (that is the separate
> three-pillar product build, §12.4–§12.10).

**Branch:** `rename/vibescan-to-trishul`
**Baseline:** source review ref `13412a5` (HEAD at start). Local `go build` + `go
test ./...` were **green** on both modules (`armur-codescanner`, `armur-cli`)
before the rename; the gate is to keep them green.

## Scope of this run (done here)
- Current public branding (README, ROADMAP, docs, CLI help/banners, examples, package display names, release notes).
- Code/build identity that is *branding* (binary names `vibescan`→`trishul`, `vibescan-server`→`trishul-server`; root CLI command `Use`).
- Compatibility surfaces: canonical config file `.trishul.yml` with legacy `.vibescan.yml` / `.armur.yml` fallback (canonical wins; a deprecation warning on legacy).

## Explicit decisions
1. **Go module paths renamed (updated 2026-11-02, founder):** root `armur-codescanner` → **`github.com/Armur-Ai/Trishul`**, nested CLI `armur-cli` → **`github.com/Armur-Ai/Trishul/cli`**. *(Original plan kept them as-is; the founder directed renaming the module too.)* Safe because both old paths were **bare, non-`go get`-able names with no external consumers**, and the modules are independent (no `replace`, the CLI doesn't import the root). All 127 root + 21 CLI import lines updated; `go build` + `go test ./...` stay green on both modules; `go.sum` unchanged (a path rename adds no dependencies). Publishing/tagging the new module path is still a separate release step.
2. **Package-registry names** (pip `trishul`, npm, VS Code extension) are rebranded **in-repo** for consistency, but **publishing** the renamed packages to PyPI/npm/Marketplace is a **separate release operation** and is NOT done here. A GitHub rename does not rename a package registry entry (§12.3).
3. **`vibescan` is not present in any Go import path or package declaration** — verified — so the branding replace is not compile-critical for imports.
4. **Immutable history is untouched**: git author/history, `CHANGELOG.md` past entries, prior release notes, copyright, and any released artifact checksums keep the word "VibeScan" as historical evidence. The gate is *no unexplained active old branding*, not zero occurrences in history.
5. **Domain `vibescan.dev` → `trishul.dev`** in copy; the `trishul.dev` domain is **not provisioned** — tracked as a follow-up, not established by this rename.

## CLI compatibility
- Canonical command/binary: `trishul`. A `vibescan` invocation should continue to work as a **deprecated alias** that delegates to `trishul` (shim/symlink installed by the packagers) — wiring tracked as a follow-up; semantics/flags/exit behavior must be preserved.

## Config precedence (canonical wins)
- CLI (`armur-cli`): read `.trishul.yml` → else legacy `.vibescan.yml` (warn: deprecated). `init` writes `.trishul.yml`.
- Server (`armur-codescanner`): read `.trishul.yml` → else legacy `.armur.yml` (warn: deprecated).
- Conflicting canonical + legacy present → the canonical file is used and the legacy one is reported, never silently merged.

## Allowlist — justified active legacy strings (owner / reason / removal criteria)
| String | Where | Reason to keep | Removal criteria |
|---|---|---|---|
| `.armur.yml` | server config fallback | legacy project-config compatibility | after a deprecation window with telemetry showing no use |
| `VibeScan` in `CHANGELOG.md` / historical release notes | docs | immutable historical evidence | never (history is preserved) |
| published pkg names on PyPI/npm/Marketplace | external registries | not changed by a repo edit; needs a release | at the package-registry rename release |

## Remote cutover
- `gh repo rename Armur-Ai/vibescan → Armur-Ai/Trishul` performed as the authorized cutover; local `origin` updated. GitHub auto-redirects the old URL. Package-registry publishing remains separate.

## Completion checklist (§12.11)
- [x] All existing builds/tests green on both modules after rename (`go build` + `go test ./...` exit 0 on `armur-codescanner` and `armur-cli`; matches pre-rename baseline).
- [x] No unexplained active VibeScan branding — zero `vibescan`/`VibeScan`/`VIBESCAN` occurrences in tracked files except this doc and the allowlist below.
- [x] No dependency/lockfile churn (`go.sum`/lockfiles untouched; only branding + config-compat code changed).
- [x] No loss of git history/identity (files moved with `git mv`; folder + remote renamed, history preserved; GitHub redirects the old URL).
- [ ] **Next steps (not in this run):** implement the three pillars (§12.4–§12.10); publish renamed packages to PyPI/npm/Marketplace (registry rename is separate, §12.3); install the `vibescan`→`trishul` deprecation shim in packagers; provision the `trishul.dev` domain; normalize repo URL casing to `Armur-Ai/Trishul`.
