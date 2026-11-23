# Trishul — Implementation Plan

**The granular, checkbox-tracked execution plan.** The [`ROADMAP.md`](../ROADMAP.md) holds the general phases and the product bet; this document holds the tasks and sub-tasks under each phase, grounded in the [Phase-0 audit](audit/PHASE-0-AUDIT.md) of commit `73e46d7`.

- **Baseline audit:** [`docs/audit/PHASE-0-AUDIT.md`](audit/PHASE-0-AUDIT.md) — capability matrix + `file:line` evidence.
- **Architecture decision:** embedded in-process engine for `trishul scan .` (no Redis/server for the default path), **server mode retained** for CI/hosted/SARIF.
- **Scope:** SAST · SCA · Secrets · IaC · Code-flow/Taint · PR review. Out-of-scope code (DAST, exploit, fuzzing, binary, smart-contract) is **isolated behind opt-in profiles, not deleted**.

---

## 🔝 Phase P — Precision, findings quality & PR output (PRIORITY TRACK, added 2026-11-23)

> **Why first:** a review of 50 high/critical findings from a 190-repo scan of the MCP and AI-agent ecosystem found **76% false positives and 2% actionable**. A PR gate is only adopted if its comments are trusted. Do this phase before making the GitHub App public.
> **Design, competitive analysis and output mockups:** [`docs/precision-and-pr-output.md`](precision-and-pr-output.md). **Evidence:** `Trishul-reports/state-of-mcp-security/false-positives.md` (internal; copy the sanitized FP cases into `testdata/precision/` per P0.2).
> **Code this builds on (PR #9):** `internal/prgate` (diff/baseline/filter/markdown), `cmd/trishul-ci`, `cmd/trishul-app` + `internal/ghapp`, `action.yml`.
> **Order:** P0 → P1 → P2 → P3, with P4 running alongside P3 → P5 → P6/P7 → P8. Each task should be roughly one commit; split further where noted.

### P0 — Measure before fixing (precision harness)

#### P0.1 Labeled corpus
- [ ] Create `testdata/precision/corpus.yaml`: a list of public repos pinned to commit SHAs. Seed it with the 190 repos from `raw/targets.json` + `raw/summary.json`.
- [ ] `scripts/precision/fetch.sh`: shallow-clone each repo at its pinned SHA into a cache directory, with symlinks off, LFS smudge off and a 2 MB blob filter. Never execute anything from the repos.
- [ ] Define the label schema `testdata/precision/labels.jsonl`: `{fingerprint_v2, repo, sha, rule_id, path, line, verdict: tp|tp_benign|fp|unclear, reason, reviewer, date}`.
- [ ] Import the 50 sample verdicts plus the targeted reviews from `raw/verification-sample.json` into `labels.jsonl`.
- [ ] Add ≥ 3 more labeled findings per rule for every rule with fewer than 3 labels, sampling at random with a fixed seed.
- [ ] Write a two-reviewer protocol (`docs/precision/labeling.md`): definitions of the verdict classes, how disagreements are resolved, and a rule that values are never copied.
- **Acceptance:** every rule ID that fired in the 190-repo scan has ≥ 5 labels, or is explicitly marked "insufficient data".

#### P0.2 Real-world FP regression fixtures
- [ ] For each FP pattern in `false-positives.md`, add a minimal sanitized fixture under `internal/<analyzer>/testdata/fp/<rule>/<case>/` that does not trigger.
- [ ] For each verified TP (Actuator `permitAll`, wildcard `.claude/settings.json`, public bucket holding inbound media), add a sanitized fixture that must trigger.
- [ ] Add a table-driven test per analyzer that walks `testdata/fp/**` (expects 0 findings for that rule) and `testdata/tp/**` (expects ≥ 1).
- **Acceptance:** `go test ./...` runs the FP/TP fixtures; the known FP fixtures fail on the current code (red), and they flip to green as the P3 tasks land.

#### P0.3 `trishul-bench` precision runner
- [ ] Add `cmd/trishul-bench`: run `prgate.ScanDir` over the corpus cache and join the results with `labels.jsonl` by fingerprint (falling back to rule+path+line±3).
- [ ] Output per-rule TP / benign / FP / unclear counts, precision, and Wilson 95% CI as markdown and JSON.
- [ ] Output a list of unlabeled findings for each rule (feeds the labeling queue).
- [ ] Add a `--rules` filter and a `--since <baseline.json>` diff mode (precision delta per rule).
- [ ] Auto-generate `docs/rules/precision.md` from the latest run.
- [ ] Add a nightly CI workflow `precision.yml` (cached corpus) that fails if any **stable** rule's precision drops by more than 5 points against the committed baseline.
- **Acceptance:** `go run ./cmd/trishul-bench` reproduces the 76% FP figure on the seeded labels.

#### P0.4 Labeling tool
- [ ] `trishul-bench label`: an interactive terminal UI that shows a finding with ±10 lines of context (secrets redacted) and records a verdict and reason to `labels.jsonl`.
- [ ] Order the queue by expected information gain: rules with the fewest labels first, then high severity.
- [ ] Never print values matched by secret rules, only their redacted previews.

#### P0.5 Production feedback signals (App)
- [ ] Record per-finding outcomes in the App store: shown inline, dismissed (with reason), resolved in a later commit, or left untouched at merge.
- [ ] Add a `/stats` section with each rule's dismiss rate and fix rate.
- [ ] Add an opt-in org setting that shares anonymized rule-level outcome counts (no code, no paths) with Armur.

### P1 — Finding model, rule metadata & confidence

#### P1.1 Finding v2 schema (`internal/findings`, new)
- [ ] Define `findings.Finding`: `rule_id`, `title`, `message`, `severity`, `confidence` (0–1 plus a band of high/medium/low), `category`, `cwe[]`, `owasp[]`, `vibe_id`, `location{path, start/end line and column}`, `snippet` (redacted, ≤ 5 lines), `evidence[]` (`{path, line, note}` steps), `remediation{text, patch?}`, `references[]`, `tags[]`, `fingerprint_v2`, `analyzer`, `rule_version`.
- [ ] Add adapters from each analyzer's current `map[string]interface{}` output to `Finding`: agentsec, each Vibe analyzer, clientsecrets, supabase, firebase, exploitability. One commit per analyzer.
- [ ] Have `prgate` consume `[]findings.Finding` directly instead of round-tripping through SARIF.
- [ ] Make the SARIF writer consume `Finding` (keep `FromScanResults` as a compatibility shim and deprecate it).
- **Acceptance:** golden tests show byte-identical SARIF for the reference app, apart from the newly added fields.

#### P1.2 Rule registry (`rules/*.yaml` + `internal/rules` loader)
- [ ] Give every rule a YAML entry: `id`, `title`, `short`, `description` (markdown), `default_severity`, `default_confidence`, `maturity` (stable/beta/experimental), `languages`, `file_kinds`, `cwe`, `owasp`, `references`, `fix` (markdown), `examples.bad`, `examples.good`, `mode_default` (block/comment/monitor).
- [ ] Write the YAML for AGENT-* (≈26 rules), VIBE-* (≈22), SUPABASE-RLS-* (5), FIREBASE-* (4), CLIENT-SECRET/SECRET (4), and EXPLOIT-* (109; batch 10 per commit).
- [ ] CI check: every rule ID an analyzer emits has a registry entry, and vice versa.
- [ ] Generate `docs/rules/<ID>.md` and a rules index from the registry. Publish them to `armur.ai/trishul/rules/<ID>` (or GitHub Pages) so comments can link to them.
- [ ] SARIF `rules[]`: `help.markdown`, `properties.security-severity` (critical 9.5 / high 8.0 / medium 5.5 / low 3.0), `properties.precision` (from the bench), `tags` (`security`, `external/cwe/cwe-N`), and `helpUri`.

#### P1.3 Confidence and priority
- [ ] Each analyzer sets confidence from evidence strength (e.g. AST-confirmed vs. regex-only, inside an executable context vs. inside a comment).
- [ ] `priority = severity_weight × confidence × context_multiplier` (lower for test, docs or generated files). Sort and gate everything by priority.
- [ ] Never show `experimental` rules in PR comments or the gate; they appear only in full reports with `--experimental`.
- [ ] Demote rules automatically: a stable rule whose bench precision is below 70% is reported as `beta` and is not shown inline.

#### P1.4 Fingerprint v2
- [ ] `fingerprint_v2 = sha256(rule_id | path | normalized_snippet_window)`, where the normalized window is the ±2 lines with whitespace collapsed and literals masked. It no longer depends on message wording.
- [ ] Rename tracking: when a PR renames a file (git similarity ≥ 50% or the GitHub compare API), match findings across the rename so they don't show as "new".
- [ ] Migration: baselines and the App DB accept both v1 and v2; `--write-baseline` writes v2.
- [ ] Tests: edits above a finding, reworded messages and renames don't change identity; real duplicates in a file remain distinct.

### P2 — Shared noise filters (one layer, every analyzer)

#### P2.1 File classification (`internal/fileclass`, new)
- [ ] Classify each file as one of: `source`, `test`, `fixture`, `example`, `docs`, `generated`, `vendored`, `minified`, `locale`, `migration`, `config`, `ci`, `agent-surface`.
- [ ] Generated: header markers (`Code generated … DO NOT EDIT`, `@generated`, `AUTO-GENERATED`, `<!-- AUTO GENERATED`), lockfiles, `*.pb.go`, `*_gen.go`, `dist/`, `build/`, `.next/`.
- [ ] Vendored: `vendor/`, `node_modules/`, `third_party/`, `external/`, `.yarn/`.
- [ ] Minified/bundled: `*.min.*`, `assets/index-*.js`, any file whose average line length is > 300 or has a line > 2,000 characters.
- [ ] Locale: `locales/`, `i18n/`, `*.po`, `*.xliff`, `README.<lang>.md`, `docs/<lang>/`.
- [ ] Respect `.gitattributes` `linguist-generated`, `linguist-vendored` and `linguist-documentation`.
- [ ] Mark the agent-surface kinds explicitly (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.cursor/**`, `.claude/**`, `mcp.json`, `.vscode/mcp.json`, `.windsurfrules`, skills dirs) so agent rules can still fire in docs-like files.
- [ ] Each rule declares the `file_kinds` it applies to in the registry; the engine skips everything else before the analyzer runs. This replaces the path heuristics in `prgate/filter.go`.
- **Acceptance:** classification unit tests on 50+ real paths; bench shows OBFS-001 volume down ≥ 60% with no TP lost.

#### P2.2 Lexical context (`internal/lexctx`, new)
- [ ] A lightweight per-language tokenizer that marks each byte range as code / comment / string / heredoc / markdown-code-fence / markdown-prose. Cover Go, JS/TS, Python, Shell, YAML, SQL, Markdown, TOML, JSON and Dockerfile.
- [ ] Shell: detect `echo`/`printf` arguments, `cat <<EOF` usage blocks and `--help` text, and mark them as `inert-text`.
- [ ] YAML: comments, and `run:` blocks (code) vs. other values.
- [ ] Give the API to analyzers: `ctx.At(path, line, col) → {kind}`. Rules declare which contexts they apply to (e.g. EXEC rules only in `code`, INSTR rules only in prose).
- **Acceptance:** fixtures of comment/echo/usage text produce no AGENT-EXEC-002/003 findings.

#### P2.3 Suppressions & config
- [ ] Inline suppression: `trishul-ignore[RULE-ID]: <reason>` on the same line or the line above. A reason is required, and it is counted and shown in the summary ("3 suppressed").
- [ ] Accept existing markers for overlapping rules: `nosec`, `nosemgrep`, `gitleaks:allow`.
- [ ] `.trishul.yml` v2 (see the design doc §4): `profile`, `comments`, `gate`, `rules.<id|glob>.{severity, mode, enabled}`, `paths.ignore`, `experimental`. Write the schema to `docs/configuration/trishul-yml.md` and a JSON Schema for editor completion.
- [ ] Policy (gate/blocking) is always read from the base branch; suppressions can come from the head, but appear in the summary as "suppressed in this PR" so reviewers see them.
- [ ] `trishul-ci --explain-config` prints the effective config.

#### P2.4 Dedupe, grouping & budgets
- [ ] Cross-analyzer dedupe: the same path+line±1 with the same CWE keeps the highest-confidence finding and lists the others in `also_reported_by`.
- [ ] Group same-rule findings in one file: more than 3 instances of a rule in one file become 1 finding with `count` and a list of lines.
- [ ] Repo-level clustering: if a rule fires in more than 20 files in one PR, show 1 summary row ("RULE fires in 37 files, likely a config-level issue") instead of 37 rows.
- [ ] PR budget: by default at most 10 inline comments and 25 summary rows, chosen by priority; the rest are in the check run.

### P3 — Rule-by-rule precision fixes (one rule ≈ 1–3 commits; each closes the matching P0.2 fixtures)

#### P3.1 Supabase (`internal/tools/supabase.go`)
- [ ] Only run in a Supabase context: a `supabase/` directory, `supabase/config.toml`, the `@supabase/*` dependency, or SQL that uses `auth.uid()`, `auth.jwt()`, `storage.objects` or the `anon`/`authenticated` roles.
- [ ] Fix the `CREATE TABLE IF NOT EXISTS <name>` parsing that produced a table named "if". Also handle quoted, schema-qualified and `public.`-prefixed names.
- [ ] Replay migrations in order (sorted by filename/timestamp) and build final state per table (RLS enabled? which policies are live?). Handle `DROP POLICY`, `ALTER POLICY`, `ALTER TABLE … ENABLE/DISABLE/FORCE ROW LEVEL SECURITY`, and drop/rename table.
- [ ] Report only the final state; point evidence at the migration that introduced the problem and the last one that touched the table.
- [ ] Treat `TO service_role` (and `postgres`/`supabase_admin`) as non-public, so it isn't flagged.
- [ ] `USING (true)` on SELECT for tables that look public (`products`, `prices`, `plans`, `categories`, `posts` with a published flag) → low severity plus a "confirm this is intentionally public" message.
- [ ] RLS-005 public buckets: high only when the bucket name or uploads look user-private (`avatars` is OK, but `chat-media`, `documents`, `invoices`, `attachments`, `uploads` with inbound writes are not); otherwise medium.
- [ ] Remediation patches: `ALTER TABLE … ENABLE ROW LEVEL SECURITY;` plus a policy template; `update storage.buckets set public=false where id='…'`.
- **Acceptance:** RLS-001 precision ≥ 85% on the bench; 0 findings on Prisma, MySQL or SQLite fixtures.

#### P3.2 Firebase (`internal/tools/firebase.go`)
- [ ] Gate on `firebase.json` / `firestore.rules` / `storage.rules` existing.
- [ ] Parse rules with match/allow scoping, so a top-level `allow read: if true` is distinguished from one inside a narrow `match` path. Know the common public-collection patterns.
- [ ] Add FP/TP fixtures for each FIREBASE-001..004.

#### P3.3 Agent obfuscation (`internal/agentsec/encoded.go`)
- [ ] OBFS-001 (invisible/bidi characters): skip runs where bidi or zero-width characters sit inside RTL-script text (Arabic, Hebrew, Persian, Urdu). Skip locale files. Only flag invisible characters adjacent to ASCII instruction text in agent-surface files or code strings.
- [ ] OBFS-001: flag Trojan-Source patterns (RLO/LRI inside code tokens) at high confidence; in prose they are info only.
- [ ] OBFS-004 (hidden HTML comments): flag only when the comment contains an imperative directed at an agent ("ignore", "you must", "run", "execute", "send", "do not tell", tool names) **and** the file is agent-surface or a README/doc an agent would read. Skip generator banners, templates and status markers.
- [ ] OBFS-003 (base64/encoded blobs): skip test data and known data formats (data URIs of images, JWT test vectors, PEM in tests). Decode and re-scan; flag only when the decoded content is an instruction or a command.
- [ ] Rate-limit: at most 3 OBFS findings per file, the rest grouped.
- **Acceptance:** OBFS family high/critical precision ≥ 80%; volume down ≥ 90% on the corpus.

#### P3.4 Agent instructions & injection (`instructions.go`, `injection.go`)
- [ ] INSTR-004: detect negation and guardrail phrasing ("do not", "never", "must not", "avoid", "don't") within the clause; guardrails are not findings.
- [ ] INSTR-*: separate "instructions to run a fixed, harmless command" (`date`, `ls`, `npm test`) from "instructions to fetch and run remote content, exfiltrate or disable safety" with a command-risk classifier (same as EXEC).
- [ ] INJ-001..003: require the payload to target the reader agent (second person, tool names, "ignore previous instructions"); only report it when it's in agent-read content (README, docs, issue templates, code comments in agent-surface).
- [ ] Use quote context: text inside markdown code fences or quoted as an example ("for example, an attacker might write …") → info.
- [ ] Fixtures: guardrail files from the corpus (ECC rules, the AGENTS.md of modelcontextprotocol/servers).

#### P3.5 Agent exec paths (`execpath.go`)
- [ ] Use P2.2 lexical context: no EXEC findings in comments, echo/printf, usage heredocs, or markdown prose outside code fences.
- [ ] EXEC-002 "pipes remote code into a shell": only when the pipe target is an interpreter running **stdin as code** (`sh`, `bash`, `zsh`, `python -`, `node -`, `iex`). Not `node -e '<fixed script>'` reading JSON, not `jq`, not `python3 -c "<fixed>"` reading stdin as data.
- [ ] EXEC-002: an allowlist of well-known installers (rustup, nvm, Homebrew, bun, deno, uv, astral, get.docker.com) → low "standard installer" instead of high. Pinned with a checksum → none.
- [ ] EXEC-003 "exfiltrates secrets": not when the secret goes to its own service, i.e. when the secret's name matches the destination host (DISCORD_WEBHOOK → discord.com, NPM_TOKEN → registry.npmjs.org, GH_TOKEN/GITHUB_TOKEN → api.github.com, PACKAGIST → packagist.org, CODEBERG → codeberg.org). Ship a map of about 50 common pairs.
- [ ] GitHub Actions: skip YAML comments; for `pull_request_target`, flag only a checkout of `github.event.pull_request.head.*` / `head_ref` from the fork plus executing PR code without an environment-approval gate.
- [ ] (Done in PR #9) loopback hosts are allowlisted.

#### P3.6 MCP trust (`mcptrust.go`)
- [ ] MCP-001: treat these as pinned: `pkg@1.2.3`, `pkg==1.2.3`, `--from <local path or wheel>`, `${VAR}/vendor/*.whl`, `git+https://…@<sha>`, and docker `image@sha256:…`. Flag `@latest`, missing versions and floating tags.
- [ ] MCP-003 (secret in MCP config): ignore placeholders (`YOUR_…`, `<…>`, `xxx`, `changeme`, `${ENV}` references), example files (`*.example.json`, `docs/**`) and golden test snapshots.
- [ ] MCP-004 (new server, informational): only in PR mode, as an "agent surface changed" table row (P5.4), never as a finding.
- [ ] New MCP-005: a remote MCP server over plain `http://` (non-loopback), or one with a token in the URL query.

#### P3.7 Permissions (`permissions.go`)
- [ ] PERM-001: high only for committed **project** settings (`.claude/settings.json`, `.cursor/…`), not for `settings.local.json`, docs or examples. Wildcard Bash/Write/WebFetch(domain:*) → high; narrow allowlists → none.
- [ ] Add a fix suggestion: move the file to `settings.local.json` (gitignored) and provide a minimal allowlist template.

#### P3.8 Attack chain (`correlate.go`)
- [ ] CHAIN-001 requires both legs individually ≥ medium confidence after the P3.3–P3.6 fixes, and one of them must be high.
- [ ] Reachability: the entry (instruction or injection) and the action (exec or permission) must be reachable by the same agent configuration (same tool family, or a repo-wide agent config).
- [ ] Never anchor on a file with no directive; the anchor is the instruction leg.
- [ ] Render the chain as evidence steps plus a mermaid diagram in the check run.
- **Acceptance:** CHAIN-001 fires in ≤ 5% of corpus repos and labeled precision ≥ 70%.

#### P3.9 LLM integration (`internal/tools/llmintegration.go`)
- [ ] VIBE-LLM-002: match only `child_process.exec/execSync/spawn` (via import/require binding), Python `exec(`/`eval(`/`subprocess` with `shell=True`, and Go `exec.Command` with LLM output flowing into it. Never match `RegExp.prototype.exec` or `db.exec`.
- [ ] VIBE-LLM-002: require LLM output data flow (a variable assigned from a completion/response API) within the same function. Use intra-procedural taint-lite.
- [ ] VIBE-LLM-001: currently medium noise in 114 repos. Narrow it to concrete sinks: LLM output into SQL, HTML (`dangerouslySetInnerHTML`, `innerHTML`), shell, file paths or eval. Otherwise mark it experimental.
- [ ] VIBE-LLM-003: review its precision and add fixtures.

#### P3.10 Route authorization (`internal/tools/routeauth.go`)
- [ ] Resolve app-wide middleware: Express `app.use(auth)`, FastAPI `add_middleware`/dependencies on a router, Next.js `middleware.ts` matchers, NestJS guards (`@UseGuards`) at controller level, Django `LoginRequiredMixin`/decorators, Flask `before_request`.
- [ ] Scan the whole handler body for auth helpers (`requireRole`, `getServerSession`, `auth()`, `currentUser`, `verifyToken`, and configurable names in `.trishul.yml`), not just the first lines.
- [ ] Public-by-design routes (health, webhooks with signature checks, auth callbacks, public GETs) → none.
- [ ] VIBE-AUTHZ-002 (IDOR): only when a path or query parameter id is used in a DB query with no ownership predicate **and** no auth context.

#### P3.11 Secrets (`clientsecrets.go`, the SECRET-001 / CWE-798 emitters)
- [ ] Skip `placeholder=`, `aria-label`, `title=`, i18n string tables, and test typing calls (`.type(…)`, `fill(…)`).
- [ ] A known-public keys list: Supabase local demo JWTs (issuer `supabase-demo`), Stripe test keys `sk_test_` → low, Firebase public web config, emulator defaults.
- [ ] Value-shape gates: require provider-format regexes or entropy ≥ 3.5 bits/char and length ≥ 20; ignore `*_IMAGE`, `*_VERSION`, `*_URL` without credentials, and `PUBLIC_*`/`NEXT_PUBLIC_*` values that aren't key-shaped.
- [ ] Context: secrets in tests → info unless provider-format and high-entropy; committed `.env` → high only when not an emulator default and not listed in `.env.example`.
- [ ] Fix the "client-side file" wording for server and test paths (use P2.1 classification).
- [ ] Optional opt-in `--verify-secrets` (separate network step, never in the App by default) that checks liveness for about 10 providers.

#### P3.12 Placeholder / insecure defaults (`placeholder.go`)
- [ ] Skip locale strings, labels and enum display names (`password: 'Password'`).
- [ ] Skip URL-normalization tests (`user:pass@` in tests).
- [ ] InsecureSkipVerify / `verify=False`: high only on production code paths; low in tooling, scripts, pentest tools and dev configs; none in prompts and docs.
- [ ] PLACEHOLDER-001..006: fixtures for each from the corpus.

#### P3.13 Abuse controls, dependencies, webhooks
- [ ] VIBE-ABUSE-001/002/003: 3,718 medium findings, unreviewed. Label 30, then decide to narrow them (only auth, signup, password reset, LLM and email endpoints without rate limiting) or demote them to experimental.
- [ ] VIBE-DEP-001..003: verify hallucinated-package detection against registry snapshots, keeping it offline with a bundled index. Add fixtures.
- [ ] VIBE-WEBHOOK-001/002: only on routes identified as webhook receivers (path contains webhook/hook/callback, or the provider SDK's construct-event pattern). Signature verification anywhere in the handler counts.

#### P3.14 Exploitability (`internal/exploitability`, 109 rules)
- [ ] Language and file-kind gating in the registry for every EXPLOIT rule: Java/Spring rules only on `.java`, `.kt`, `pom.xml`, `build.gradle*`, `application*.yml/properties`; never on Go/JS sources. This fixes the Fastjson/SpEL/Text4Shell hits in Go files. One commit per 10 rules.
- [ ] Skip minified/bundled files (P2.1) for all EXPLOIT rules. This fixes the SQLI hit in a Vite bundle.
- [ ] EXPLOIT-GCP-GCS-PUBLIC-001: match only `google_storage_bucket_iam_*` / `storage.objectViewer` with allUsers, not `run.invoker`.
- [ ] EXPLOIT-FILE-UPLOAD-001: require a write sink (fs write, storage put) for the original filename.
- [ ] EXPLOIT-NEXTJS-29927-001: critical only when `middleware.ts` performs auth; i18n-only middleware → low; no middleware → none.
- [ ] EXPLOIT-CORS-CREDS-001: skip JSDoc/comments; see the deletion of `Access-Control-Allow-Credentials` on the following lines.
- [ ] EXPLOIT-JWT-NONE/NOVERIFY: skip creation of `alg:none` placeholder tokens and comments describing fixes; require verification to actually be disabled on a decode path.
- [ ] EXPLOIT-SPRING-ACTUATOR-001 (a verified TP): raise confidence when `permitAll` on `/actuator/**` and exposure `*` occur together; add a heapdump/env-specific message.
- [ ] Review the remaining EXPLOIT rules in batches of 10 against the bench; demote any with precision below 60%.

### P4 — Make true positives more valuable

#### P4.1 Evidence & explanations
- [ ] Every finding carries ≥ 1 evidence step (the matched construct plus why it matters). Chains and taint carry multiple steps.
- [ ] Snippets are rendered with the offending line marked and secrets redacted.
- [ ] A per-rule "why this matters" paragraph and "how to fix" from the registry, linked to the rule docs page.
- [ ] SARIF `codeFlows`/`relatedLocations` for chains and multi-location findings.

#### P4.2 Autofix (deterministic, as GitHub suggestion blocks)
- [ ] Autofix framework: a rule returns a `Patch{path, start_line, end_line, replacement}` only when it is deterministic and local, and the patch is validated by re-scanning the patched file in memory.
- [ ] MCP-001: pin the version. Offline, from a lockfile or package.json if present; otherwise suggest `@<version>` with a TODO and no suggestion block.
- [ ] SUPABASE-RLS-001: append an `ENABLE ROW LEVEL SECURITY` statement.
- [ ] RLS-005: make the bucket private.
- [ ] PERM-001: narrow the wildcard permissions to a minimal list.
- [ ] Spring Actuator: set `exposure.include` to `health,info`.
- [ ] Secrets: replace the literal with an env-var read and add the key to `.env.example`.
- [ ] Webhook: add a signature-verification snippet (for the Stripe, GitHub and Svix SDKs).
- [ ] SARIF `fixes[]` so GitHub code scanning can offer them too.

#### P4.3 Optional AI triage (opt-in, BYO key, never decides alone)
- [ ] `internal/ai/triage`: for each high/critical finding, send the rule description plus a ±30-line snippet (scanned content clearly delimited as untrusted data, never as instructions) and receive `{likely_fp: bool, rationale, confidence}`.
- [ ] Guardrails: prompt-injection-resistant prompt; output is a label only, never a severity raise; cost cap per PR; off by default; content is never sent for repos the org hasn't enabled.
- [ ] Eval harness against `labels.jsonl`: report triage precision/recall; ship only if it removes ≥ 50% of FPs while losing ≤ 2% of TPs.
- [ ] UI: an "AI-assessed: likely false positive" collapsed section, never silently dropped.

#### P4.4 Agent-surface change summary (Socket-style)
- [ ] In PR mode, diff the agent surface: new or removed MCP servers (with command and pinned version), changed instruction files (with a summary of added directives), new or broadened permissions, and new install hooks.
- [ ] Render it as a "Your AI agent's environment changed" table in the summary and check run, even when there are no findings (informational, collapsed).

### P5 — PR output redesign (see the design doc §2–3)

#### P5.1 Check run (full record)
- [ ] Title format: `N new issues (x critical, y high) · gate passed|failed` / `No new issues`.
- [ ] Summary sections in this order: headline; agent-surface callout; severity/category counts; findings grouped by category with evidence; chain mermaid diagrams; fixed list; outside-the-diff list; suppressed list; config, version and duration footer.
- [ ] Respect GitHub's 65,535-character limit with smart truncation (keep the headline and top findings; link to a full SARIF artifact or the dashboard).
- [ ] Annotations only on changed lines (P5.2 diff map); `annotation_level` from priority; titles use the rule title, not the bare ID.
- [ ] Conclusion: `success` / `neutral` (non-blocking findings) / `failure` (gate) / `action_required` when configuration is broken.
- [ ] Add a "Re-run" button through the `requested_action` check-run actions: rescan, and create a baseline PR.

#### P5.2 Inline review comments
- [ ] Build a diff map from the PR files API (`patch` hunks) and map finding lines to diff positions; only lines inside hunks are eligible.
- [ ] Post one PR **review** per scan (`POST /pulls/{n}/reviews`, `event: COMMENT`) with up to the budget (P2.4) of comments, so it's batched rather than spammy.
- [ ] On later pushes, resolve or minimize Trishul's outdated comments (GraphQL `minimizeComment` / `resolveReviewThread`) when their fingerprint is gone; never re-post an existing fingerprint.
- [ ] Comment template per the design doc §3.2: severity badge, title, why, `suggestion` block when an autofix exists, collapsible details, triage footer.
- [ ] Permissions: inline comments need `pull_requests: write` (already granted). Adding `contents: write` is **not** needed.
- [ ] Action parity: `trishul-ci --github-review` posts the same review with `GITHUB_TOKEN` (and degrades to the summary only on fork PRs).

#### P5.3 Summary comment (sticky)
- [ ] Rewrite `prgate.Report.Markdown()` to the design doc §3.1 layout: headline line, agent-surface callout, top-5 table with linked titles, gate line, collapsed outside-diff and pre-existing sections, triage footer.
- [ ] `comments.summary: auto` keeps current behaviour; `require_changes` updates the comment only when the finding set changes (avoids notification noise).
- [ ] Golden snapshot tests for: 0 findings, 1 finding, 30 findings (truncation), a chain, fixed-only, suppressed, fork PR, and blocked gate.

#### P5.4 Commands & triage in the PR
- [ ] Parse `issue_comment` and `pull_request_review_comment` webhooks (subscribe to the events and update the app manifest; owners must approve the new events).
- [ ] `@trishul-security ignore <reason>` replying to an inline comment: record the dismissal (fingerprint, reason category from GitHub's set: false positive / won't fix / used in tests, user, PR), resolve the thread, and acknowledge it.
- [ ] `@trishul-security rescan`, `@trishul-security explain` (expanded rule docs), `@trishul-security pause` / `resume` (per PR), `@trishul-security baseline` (opens a PR adding the current findings to `.trishul-baseline.json`; needs `contents: write`, so make it optional and documented).
- [ ] Authorization: only users with write access to the repo can dismiss; check the collaborator permission API.
- [ ] Learnings: dismissed fingerprints apply to future PRs in that repo (org-wide optional); listed on the dashboard and revocable.

#### P5.5 Quality gate & modes
- [ ] Per-rule `mode` (monitor = check run only, comment = summary + inline, block = can fail the gate), with defaults from the registry.
- [ ] `profile` presets: quiet (critical/high, high confidence, no medium), balanced (default), thorough (includes medium and beta rules).
- [ ] The gate is evaluated only on new findings with `mode: block` and confidence ≥ `gate.min_confidence`.
- [ ] Document how to make the check required in branch protection, with a screenshot in the docs.

#### P5.6 Visual consistency
- [ ] One severity palette and icon set shared by CLI, markdown, SVG badge and dashboard (`internal/present` package).
- [ ] Rule titles and docs links everywhere instead of bare IDs.
- [ ] Badge: grade computed only from stable rules with confidence ≥ medium; examples, fixtures and tests are excluded from the grade (fixes Trishul's own "F").

#### P5.7 Dashboard (later; after P5.1–P5.5)
- [ ] GitHub OAuth login, restricted to repos the user can access via the user-to-server token.
- [ ] Per-repo page: open findings on the default branch, trend, dismissals and learnings, config preview, recent PR scans.
- [ ] Org page: repos, adoption, and top rules by dismiss rate (feeds P0.5).

### P6 — App platform hardening

- [ ] Postgres store (replaces the JSON file): installations, repos, scans, findings (fingerprints only, no code), dismissals, events.
- [ ] Durable job queue (Postgres `SKIP LOCKED`); jobs survive restarts; retries with exponential backoff; dead-letter list.
- [ ] Webhook idempotency via `X-GitHub-Delivery` dedupe; handle redeliveries.
- [ ] Startup reconciliation: mark any `in_progress` Trishul check runs older than 10 minutes as `neutral` with "scan interrupted, re-run". This fixes the stuck checks seen on PR #9.
- [ ] Cache base-scan results by `(repo, merge_base_sha, rule_pack_version)`, which roughly halves PR scan time.
- [ ] Incremental scans: only analyze changed files plus files that analyzers declare as dependencies (e.g. all migrations for RLS replay, all agent-surface files for chains).
- [ ] Sandbox scans in a subprocess with rlimits (CPU, memory, files), a seccomp/no-network namespace (nsjail/bubblewrap), and a read-only bind-mount of the extracted tree.
- [ ] Respect rate limits (`X-RateLimit-*`, secondary limits); add per-installation concurrency caps.
- [ ] Observability: Prometheus `/metrics` (queue depth, scan latency p50/p95, API errors, findings per scan), structured JSON logs, and alerting (healthz monitor plus an error-rate alert).
- [ ] Reserve a static IP for the VM (an ephemeral IP has changed before); add backups for the DB; write a runbook in `docs/github-app.md`.
- [ ] Privacy policy and terms pages (needed for a Marketplace listing). Uninstalling deletes the installation's data within 30 days.
- [ ] Skip draft PRs by default (configurable); a bot PR policy (scan Dependabot/Renovate but comment only on critical).
- [ ] Load test: 50 concurrent PR events against a 2-vCPU VM; document capacity; plan a container/Cloud Run move when needed.

### P7 — CLI / Action parity & developer experience

- [ ] `trishul review` (CLI): a terminal rendering of the same report against `origin/main` (rich table, colors, snippets) for running before pushing.
- [ ] Pre-commit hook (`.pre-commit-hooks.yaml`) running `trishul-ci --base HEAD --staged-only` in quiet profile.
- [ ] `trishul-ci --format github-review|sarif|json|markdown|text`, with all formats coming from the same `internal/present` package.
- [ ] VS Code extension (`packages/vscode`): show findings from `trishul-ci --json` for the open file; quick-fix via autofix patches.
- [ ] MCP tool: return findings in the v2 schema so coding agents can fix them (closes the loop with Phase 2).

### P8 — Validation & launch gate

- [ ] Re-run the 190-repo corpus scan with the new rule pack; regenerate `docs/rules/precision.md`.
- [ ] Two-reviewer label of a fresh random sample of ≥ 100 high/critical findings; publish the precision with its confidence interval internally.
- [ ] Gate check against the design doc §5 targets (≥ 80% high/critical precision, ≤ 5% comments on clean PRs, median ≤ 30 s).
- [ ] Dogfood: install the App on all Armur-Ai repos for 2 weeks; review every dismissal; fix the top 3 FP causes.
- [ ] Update `report-draft.md` with the new numbers and re-verify each claim before considering publication; the responsible-disclosure windows must have closed.
- [ ] Then follow `docs/launch/distribution-playbook.md`: tag the release, make the App public, list on the Marketplace.

## How to use this file

- `[ ]` not started · `[~]` in progress · `[x]` done & tested. Update the box in the PR that lands the task.
- **✨ NEW** marks capabilities added beyond the original spec/roadmap — proposed enhancements that make Trishul materially better.
- Every task names its **acceptance check**. A box is only ticked when its check passes on a clean machine.
- Each phase ends with an **exit test** a stranger can reproduce. Phases are ordered by dependency, not date.

## Engineering invariants (apply to every task)

- [ ] The scan target is **read-only**: no task may write, move, delete, or filter files inside it. (Invariant test in Phase 0.3.)
- [ ] **No plaintext secret** may appear in any output sink, ever. (Canary test in Phase 0.1.)
- [ ] A **skipped/unavailable scanner is never a clean result** — it is surfaced as `skipped`.
- [ ] **No network during a scan** unless explicitly configured (tool downloads and DB updates are separate, opt-in steps).
- [ ] Scanned content is **untrusted data**: never executed, never allowed to steer Trishul's own LLM calls.
- [ ] Every new detector ships with **one vulnerable and one safe fixture**; CI fails if a listed tool has no passing fixture.

---

## Phase 0 — Make the promise true & make it safe (v0.1)

> Goal: a stranger can install Trishul and run `trishul scan .` on a real project, get honest results, and have their files untouched. Everything else depends on this.

### 0.1 Secrets redaction — **P0 blocker** (`internal/tools/trufflehog.go`, `pkg/format.go`, sinks)
- [x] Redact at the source: `formatSecretIssue` now emits `secret_preview` (via `redact.Mask`) + `fingerprint` (via `redact.Fingerprint`), never the raw value. New stdlib-only package `internal/redact` with full tests.
- [x] No raw-value field reaches the result map — `secret_preview`/`fingerprint` replace the `secret` key, so nothing downstream can receive the plaintext.
- [x] All sinks covered: the leak had a single source (`formatSecretIssue`); its map is the only path to the JSON API, Redis, and webhooks, so the one change closes every sink. (Verified trivy/binary carry no captured secret value; the webhook HMAC secret is unrelated and intentionally untouched.)
- [x] Replaced the leak-asserting test with the inverse assertion (raw value absent; preview + fingerprint present).
- [x] ✨ **Canary regression test** (`secret_canary_test.go`): a synthetic secret fed through categorize → convert → JSON-marshal; fails if the plaintext or an interior fragment survives. Runs under `go test`, so CI gates it once green.
- **Acceptance:** ✅ canary test passes; serialized result contains no plaintext.

### 0.2 Fix `trishul scan .` (local directory) end-to-end (`cli/internal/api/api.go:110-112`, `cli/cmd/scan.go`)
- [ ] Implement local-directory scanning (currently rejected). Route `.`/relative/absolute dir targets through the new embedded engine (0.5), not the file-upload path.
- [ ] Auto-detect languages & ecosystems per directory; make `-l/--language` optional everywhere (incl. repo URLs).
- [ ] Support monorepos (multiple ecosystems in one tree) — per-subtree detection.
- [ ] Add `--deep` as an alias/superset of `--advanced`; make `--advanced` a **superset** of the standard scan and count its findings in the summary (`scan.go` summary bug).
- **Acceptance:** `trishul scan .` on `examples/vibe-coded-app` returns findings; `trishul scan ./path/to/file` and `trishul scan <url>` still work.

### 0.3 Read-only hardening (`pkg/utils.go:202-238`, `internal/tasks/tasks.go`)
- [~] Guard `RemoveNonRelevantFiles` so it no-ops on any non-managed (user) path. _(Full switch to per-tool include-globs — so pruning is never needed at all — is deferred to a follow-up; the destructive behaviour on user source is already neutralised.)_
- [x] Guard every `os.RemoveAll` (`tasks.go:306,550,590`) via `utils.SafeRemoveAll`, which refuses any path outside a managed working root.
- [x] `RunScanTaskLocal` (`tasks.go:193`) can no longer mutate the target: its `RemoveNonRelevantFiles` call no-ops on the user path (not managed).
- [x] ✨ **Invariant test** (`pkg/readonly_test.go`): snapshots a fixture tree's per-file hashes and asserts a non-managed target is byte-identical after pruning; also confirms pruning still works inside a managed copy.
- **Acceptance:** ✅ invariant test passes; `SafeRemoveAll`/`IsManagedPath` unit-tested.

### 0.4 Honest scanner status (`internal/tools/*`, `internal/tasks/tasks.go`, `cli/cmd/{scan,run}.go`)
- [x] ✨ Conservative **capability map** (`capability.go`): required binary per tool + `RequiredBinary`/`IsToolSkippable`. _(min-version/licence/resource-limit fields are a follow-up; required-binary is in.)_
- [~] **Existence detection** done (`ToolAvailable` via `exec.LookPath`; runner records known-missing tools as skipped). _Version comparison (`--version` vs min) still to add._
- [x] ✨ **Structured execution result** enum (`result.go`): `completed_with_findings`/`completed_clean`/`skipped_unavailable`/`failed`/`timed_out`/`cancelled` + `ClassifyOutcome`.
- [x] Surface `scan_errors` and skipped tools in CLI output (`scan.go printScanErrors`); the runner now emits a skip for known-missing tools (`tasks.go withTimeout`).
- [~] Migrate `exec.Command` → `exec.CommandContext`: helper `RunToolCommand[Stdout][InDir]` done (real process-kill timeout + availability); **adapter migration in progress** (delegated).
- **Acceptance:** ✅ a known-missing tool is reported as skipped (not clean) in the CLI output and `scan_errors`.

### 0.5 Embedded engine for the default path (`cli/`, `internal/tasks`, `internal/engine` ✨ new)
- [ ] ✨ Extract the scan pipeline into an importable **`internal/engine`** library callable in-process (no HTTP, no Redis).
- [ ] Make the CLI call the engine directly for `scan`; keep `trishul serve` for the API/CI use case.
- [ ] Wire the existing **embedded Redis** (`internal/redis/embedded.go`, currently dead) OR a queue-free in-process worker pool for local runs; remove the hard Redis dependency from the default path.
- [ ] Keep the server + asynq + SARIF-API path working (used by `armur-scan.yml`); add a regression test for it.
- **Acceptance:** `trishul scan .` works with no Redis and no server process running.

### 0.6 Findings normalization & SARIF correctness (`internal/models`, `internal/tools/severity.go`, `pkg/sarif`)
- [x] **Severity normalizers unified**: one canonical `models.NormalizeSeverityString`; `tools.NormalizeSeverity` delegates its generic path to it; `models.normalizeSev` too. No divergent copy. (Avoided the cycle by putting the shared map in the low-level `models` package.)
- [ ] Add missing schema fields: **scanner version**, **data-flow/trace** (for Phase 1), structured evidence. _(ToolVersion helper exists; wiring into findings pending.)_
- [x] ✨ **Line-insensitive, unified fingerprint**: `Finding.ComputeID` now hashes Tool|File|RuleID|normalized-Message (no raw line); the dedup key is aligned to the same basis. SARIF `partialFingerprints` likewise line-insensitive.
- [x] SARIF: `partialFingerprints` + **deterministic rule ordering** + **consumes all categories** (security, secrets-redacted, SCA, IaC) with stable per-rule ids (no `UNKNOWN` collapse).
- **Acceptance:** ✅ SARIF carries stable fingerprints, reproducible ordering, and full category coverage; severity + finding-identity unified.

### 0.7 Profiles & signal-over-volume (`internal/tasks`, `cli`)
- [x] ✨ **Profiles** `security` (default) / `quality` / `web3` / `all`, selectable via `--profile` (exported as `TRISHUL_PROFILE`, inherited by the auto-started server) and classified in `internal/tools/profiles.go`.
- [x] Default profile **omits** golint/gocyclo/radon/pydocstyle/vulture/godeadcode/jscpd/cargo-geiger (the runner skips quality tools unless `quality`/`all`); smart-contract tools stay behind `web3`.
- **Acceptance:** ✅ default scan runs security tools only; `--profile quality|web3|all` opts in; gating unit-tested.

### 0.8 Truth in packaging, branding & CI (`.github/workflows`, `action.yml`, `packages/*`, `cli/armur-cli`)
- [x] Fix CI: align test/lint/release workflows to Go `1.25` (the skew that reddened `main`).
- [x] Remove the committed **14 MB `cli/armur-cli`** binary; gitignore built binaries.
- [x] Correct overclaims in satellite artifacts (`.goreleaser.yml`, npm/pip/vscode manifests, `docs/tools/supported-tools.md`, docs-site Architecture) to match the honest README.
- [~] `armur → trishul` rename: MCP tool names ✅, Action ✅, pre-commit hooks ✅, docs-site ✅; config file already canonical `.trishul.yml` (legacy fallback) ✅. _Remaining: docker image refs, the PyPI `trishul` collision._
- [ ] Hide CLI commands whose backends aren't wired (`review`, `explain`, `fix`); fix/remove the dead `--diff`/`--staged-only` flags.
- [x] Fix `BatchScan` scan-type literal mismatch (used the string literals, worker switches on the constants).
- **Acceptance:** ✅ CI aligned/green, binary removed, overclaims corrected, BatchScan fixed; a few rename tails + command-hiding remain.

**Phase 0 exit test:** on clean macOS and Ubuntu, `trishul scan .` against `examples/vibe-coded-app` finishes <60 s, reports the planted findings, leaves the directory byte-identical, surfaces any skipped tools, leaks no plaintext secret, and makes no network calls beyond opt-in tool/DB updates.

> **Exit-test status (this run):** leaves the directory **byte-identical** ✅ (invariant test), **leaks no plaintext secret** ✅ (canary test), **surfaces skipped tools** ✅, **green build/test/CI** ✅. **Still required:** `trishul scan .` must actually run (needs the embedded engine, 0.2/0.5) — the one remaining blocker before the full exit test can pass end-to-end.

---

## Phase 1 — Reliable core + vibe-native detection (v0.2–v0.3)

> Goal: the six capabilities each have genuinely-wired, structured, tested adapters, plus Trishul's own rule packs for the Vibe Top 10. This is the moat.

### 1.1 Revive the in-scope dead adapters (18 orphaned — see audit §4)
- [ ] Secrets: wire **gitleaks** (currently orphaned) for redundancy + git-history scanning alongside TruffleHog.
- [ ] SCA: wire **govulncheck, grype, `sca.go`** (npm/pip/composer/cargo/bundler), **`sbom.go`** (CycloneDX/SPDX), and dependency-check beyond Java.
- [ ] Decide per adapter: revive vs remove (csharp, swift, openapi, testgen, threatmodel, depupdate) — track decisions in the PR.
- **Acceptance:** each revived adapter is registered, parses structured output, and has positive+negative fixtures.

### 1.2 SAST engine & rule packs (`internal/tools/semgrep.go`, new rule dir)
- [ ] Stop `--config=auto` (network + licence risk); ship a **pinned, licence-clean rule set**, offline by default. Evaluate **Opengrep** as the default engine.
- [ ] Add the ESLint security stack (eslint-plugin-security, no-unsanitized, @next/eslint-plugin-next) for the core JS/TS case.
- [ ] ✨ Confidence scoring per finding; auto-suppress `test/`, `vendor/`, generated, and `node_modules` paths by default.

### 1.3 Taint / code-flow — **spec priority, currently Missing** (Phase 2 in spec, pulled forward)
- [ ] Integrate a **real source→sink engine** (Opengrep/Semgrep taint-mode rules; evaluate CodeQL packs where licence permits) for JS/TS, Python, Go, Java.
- [ ] Populate the schema's **data-flow field** with the actual supported path; when a path can't be completed, report the limitation explicitly — **never invent steps with an LLM**.
- [ ] Rebuild `internal/attackpath` as correlation **on top of** real flows, not a substitute.
- [ ] Vuln classes: SQLi, command injection, SSRF, path traversal, unsafe deserialization, XSS, unsafe-exec, missing-authz (where evidence exists).
- **Acceptance:** a cross-file SQLi fixture yields a finding whose evidence shows the real source→sink path.

### 1.4 Vibe-native analyzers (build-ourselves moat — maps to Vibe Top 10)
- [x] **V01 client-secret exposure** (`internal/tools/clientsecrets.go`): secret-shaped values behind `NEXT_PUBLIC_`/`VITE_`/`EXPO_PUBLIC_`/`REACT_APP_`; service-role JWT / private key in client-side files; committed `.env` secrets. Emits only redacted previews (no-leak test). Wired on every scan; e2e-tested through the engine. _(Early in Phase 0 as a built-in, dependency-free analyzer.)_
- [x] **V03 open data layer — Supabase** (`internal/tools/supabase.go`): RLS off, `using (true)`, `anon` grants, `security definer` w/o `search_path`, public buckets (SUPABASE-RLS-001..005). Wired + e2e-tested. _(Firebase rules analyzer still to do.)_
- [ ] **V02 missing authorization:** route inventory for Next.js (`app/**/route.ts`, `pages/api/**`, server actions), Express, FastAPI, Flask, Hono, Supabase Edge Functions; flag data handlers with no session/token check; IDOR heuristic.
- [ ] **V04 dependency intelligence:** ✨ hallucinated/typosquat/dependency-confusion scoring (registry existence, age <30 days, download volume, edit-distance to popular names); OSV `MAL-` + GuardDog heuristics; offline snapshot of popular names.
- [ ] **V06/V07/V08 placeholder & abuse:** hardcoded JWT/session secrets, default creds, `verify=False`, `cors({origin:"*"})` with credentials, debug flags, security `TODO`s; unverified Stripe/Clerk/Svix webhooks; prices/roles trusted from request body; missing rate-limit on auth/LLM routes.
- [ ] **V09 unsafe LLM integration:** replace `llmsecurity.go` regex with taint rules (user input → prompt; model output → eval/SQL/shell/HTML); browser-side provider keys.
- **Acceptance:** each Vibe Top 10 class has ≥1 rule with vulnerable+safe fixtures; default profile = zero findings on safe variants.

### 1.5 Reporting & DX
- [ ] Rebuild the text report (file+line, full message, one row/finding, totals that match).
- [ ] Plain-English output: what it is, why an attacker cares, the fix; Vibe Top 10 ID + CWE per finding.
- [ ] ✨ **Launch-readiness score** with the top-3 things to fix first.
- [ ] ✨ `.trishul.yml` **policy-as-code**: severity gates, path ignores, rule enable/disable, documented.

**Phase 1 exit test:** on the fixture corpus, every Vibe Top 10 class fires on its vulnerable fixture and stays silent on its safe fixture; `trishul scan .` is reproducible (same input → same fingerprints).

---

## Phase 2 — In the agent loop (v0.4)

> Goal: Trishul becomes part of how AI-written code is made — in Claude Code, Cursor, Copilot, Codex.

### 2.1 MCP server that ships (`internal/mcp` — currently unreachable)
- [ ] Wire `StartMCPServer` into a real binary (`trishul mcp`); rename tools `armur_* → trishul_*`.
- [ ] Narrowly-scoped tools: scan project, scan changed files, retrieve findings, explain a finding, propose a remediation, ✨ **verify a proposed fix** (apply in a scratch copy, re-scan, confirm it closes the finding and adds none).
- [ ] Keep the hard **no-shell-exec** constraint (already satisfied); document the tool permission surface.
- **Acceptance:** Claude Code/Cursor can call `trishul` MCP tools; no tool grants arbitrary command execution.

### 2.2 Prompt-injection safety for Trishul's own AI (`internal/ai/*` — currently unguarded)
- [ ] ✨ **Untrusted-content guard:** fence and label scanned code/manifests in prompts (`explain.go`, `techdetect.go`); separate system instructions from scanned data; never execute model-suggested commands (`techdetect.go` RunCommand/BuildCommand stay inert).
- [ ] No secrets/proprietary source sent to an external model without explicit authorization (reuse the redaction layer).
- **Acceptance:** an adversarial fixture (a file containing "ignore previous instructions…") does not alter Trishul's analysis or trigger any action.

### 2.3 Editor & shell hooks
- [ ] `trishul hooks install`: Claude Code `PostToolUse` (scan after edit) + `Stop` (block on new critical) hooks; Cursor equivalent.
- [ ] Pre-install guard: check `npm/pip/npx` targets against dependency intelligence before they run (fixes the dead `--staged-only` pre-commit path).

### 2.4 Agent-surface security — **spec requirement, currently Missing** (V10)
- [ ] ✨ `trishul agent-scan`: evidence-based detection of suspicious changes to `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, agent skills, MCP configs, coding-agent hooks, CI workflows, install/build hooks — hidden/bidirectional Unicode, injected instructions, expanded tool permissions, disabled checks, new network destinations, install-time code execution, unpinned `npx -y`/`uvx` MCP servers, secrets in MCP config.
- [ ] Treat these files as untrusted data; **never execute** instructions found in them; evidence-based, not keyword-blocking.
- **Acceptance:** a benign agent-config change is clean; a malicious one (hidden Unicode / permission escalation) is flagged with evidence.

### 2.5 Fix loop & guard rules
- [ ] `trishul fix --prompt`: paste-ready fix prompt (file, line, vulnerable code, required property of the fix, how to verify) — no API key needed.
- [ ] `trishul guard`: write a stack-tailored security section into `CLAUDE.md`/`AGENTS.md`/`.cursor/rules`/`copilot-instructions.md`.
- [ ] ✨ **AI-provenance mode:** identify AI-authored commits; `trishul scan --ai-authored` scans only that code; reports break findings down by author type.

**Phase 2 exit test:** in a recorded session, an agent writes a Supabase table without RLS, the hook fires, the agent receives the finding and the verify-loop confirms the fix — with no human typing.

---

## Phase 3 — PR review & scanner breadth (v0.5)

> Goal: a diff-aware PR gate that distinguishes new from pre-existing findings, plus broader, benchmarked tool coverage.

### 3.1 PR / diff-aware review (`internal/agent/pr_review.go` — currently stub; marks all findings "new")
- [ ] Real `trishul pr --base <ref>`: base-vs-head scan + comparison (not whole-head-branch).
- [ ] Changed-file/line mapping; **new vs pre-existing** via the stable fingerprints from 0.6.
- [ ] ✨ Keep findings that are newly-introduced via **changed data-flow or config** even on unchanged lines (don't discard everything outside the diff).
- [ ] Baseline suppression with an auditable baseline file; rename/move handling.
- [ ] SARIF output + GitHub PR annotations/inline comments; configurable severity policy & exit codes.
- [ ] Fix the composite `action.yml` (CLI must honor `--format`/file output) or converge on the server-based `armur-scan.yml` path; publish a Marketplace Action with SARIF upload.
- **Acceptance:** a PR that introduces a vuln is flagged as *new*; a pre-existing one is not re-reported; annotations appear inline.

### 3.2 Scanner breadth (per ROADMAP §8 expansion plan)
- [ ] Tier-1/2 additions, each with pinned version, provisioning entry, normalizer, fixture, Vibe Top 10 mapping: ast-grep, Ruff `S`, njsscan, zizmor/actionlint (CI hardening — spec's insecure-GitHub-Actions requirement), Squawk, Splinter (live Supabase), Syft (SBOM), retire.js, GuardDog, Snyk agent-scan.
- [ ] ✨ Generate the README tool matrix **from the registry in code**; CI fails if a listed tool has no passing fixture.
- [ ] `trishul tools install`: pinned, checksummed downloads into `~/.trishul/tools` (no `pip/go install` at scan time); `--docker` fallback runs the same pipeline.
- **Acceptance:** the tool matrix is code-generated and every listed tool has a passing fixture.

---

## Phase 4 — Proof & distribution (v0.6–v1.0)

> Goal: public, reproducible evidence that Trishul catches what AI coding tools generate.

- [ ] ✨ **VibeBench:** fixed app prompts run through each major AI coding tool; commit outputs, scan them, publish numbers + method. Doubles as the precision/recall harness (OWASP Benchmark/Juliet where applicable + curated vuln/fixed pairs).
- [ ] "State of Vibe-Coded Security" report, refreshed quarterly.
- [ ] ✨ **Reachability/exploitability triage + VEX:** emit OpenVEX statements (reachable/affected/not-affected) to cut dependency-noise; "confirmed reachable" vs "possible".
- [ ] ✨ **Incremental/cached scans:** content-hash cache keyed by file+tool+rule-version for fast re-scans; changed-files mode.
- [ ] Web scan at trishul.dev (paste a public repo URL → report); "Scanned by Trishul" badge with grade.
- [ ] VS Code / Cursor / Windsurf extension (one codebase); docs site matching the product; `CONTRIBUTING.md` rule-writing guide.
- **Acceptance:** VibeBench recall above an agreed bar for every Vibe Top 10 class and FP rate on the safe corpus below an agreed bar (bars set from the first run).

---

## Phase 5 — Runtime verification (after v1.0, demand-driven)

> Out-of-scope for the current upgrade; isolated code stays in-tree. Returns here as *verification of static findings*.

- [ ] `trishul probe <url>` for owned apps only (ownership proof required): exposed `.env`/`.git`, source maps, keys in bundles, anon-readable Supabase tables, open Firebase, headers.
- [ ] Wire the isolated sandbox/DAST/exploit packages **only** to confirm static findings ("confirmed exploitable" vs "possible").
- [ ] Attack-path view built on confirmed findings.

---

## Cross-cutting tracks (run continuously)

- **Security of the scanner itself:** read-only invariant, secret redaction, prompt-injection guard, no-network-by-default, no-shell-exec MCP, supply-chain-pinned tool installs.
- **Testing & benchmark:** per-adapter positive+negative fixtures; the canary secret test; the read-only invariant test; the reproducibility test; VibeBench as the precision/recall harness. **No invented benchmark numbers.**
- **Determinism & provenance:** every scan emits a manifest (tool versions, rule-pack version, vuln-DB freshness, profile, skipped tools) so results are reproducible and auditable.
- **Docs honesty:** nothing is advertised before its phase exit test passes; the README status table stays truthful.

---

## Target capability matrix (definition of done)

| Capability | Today | Target (this plan) |
|---|---|---|
| SAST | Partial | Working+tested, pinned rules, taint-capable engine |
| SCA | Partial | Working+tested, SBOM + hallucinated/malicious-pkg intel |
| Secrets | **Broken (leak)** | Working+tested, **redacted everywhere**, gitleaks+trufflehog |
| IaC | Working | Working+tested + Supabase RLS / Firebase / CI-hardening |
| Taint / code-flow | **Missing** | Working, real source→sink evidence paths |
| PR review | Unreachable | Working, diff-aware, new-vs-existing, SARIF + annotations |
| Agent-config security | **Missing** | ✨ Working, evidence-based, untrusted-by-default |
| Local-first `scan .` | **Broken** | Working, embedded, no Redis/server needed |

*Each phase ships with a refreshed "capability matrix — after" appended to the audit doc, per the deliverables list.*

---

## Capability 7 — AI Agent Supply-Chain Security (`internal/agentsec`)

> **Incremental extension, not a new project.** Deepens the agent-surface work (Phase 2.4). **Reuse** the PR diff engine (Phase 3.1), the shared `Finding` schema + stable fingerprints, the SARIF/annotation/MCP reporting, and the existing config parsing. No duplicate scanners or pipelines. New home: `internal/agentsec` (deterministic parsers + a semantic layer + a correlation graph), wired into the normal scan pipeline and a dedicated `trishul agent-security` command. Passive by default; an external LLM is never mandatory.

### Threat model (encode as fixtures, §F)
- [ ] Attacker controls PR content (source, comments, Markdown, test fixtures, package scripts, CI workflows, agent-config, MCP config) but **not** trusted host policies.
- [ ] Protected agent workflows: review PR · checkout PR · read repo instructions · run tests/builds · install deps · invoke tools · propose/apply changes.
- [ ] For each workflow, enumerate the **trust boundary** (untrusted repo content → agent action) the analysis reasons about.

### Component 1 — Agent instruction analysis
- [x] Structural parse of `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.cursor/rules/*`, `.github/copilot-instructions.md`, Claude/Cursor skills, hooks config.
- [x] Detect instruction-override / system-or-developer-message impersonation / authority-escalation language (e.g. "ignore previous", "you are now", fake "SYSTEM:"/"DEVELOPER:" framing) — reported as *suspicious instruction*, never "agent compromised".
- **Acceptance:** malicious instruction-file fixtures flagged with file/line + trust-boundary; benign instruction files clean.

### Component 2 — Prompt-injection detection (semantic layer)
- [x] Heuristic + optional-LLM detection of injection in comments, README/Markdown, test fixtures, tool-output-laundered text. The semantic layer is **never the sole basis for a high-confidence claim** (must be corroborated by a deterministic/correlation signal).
- [x] Treat all scanned text as data; Trishul's own analysis must not follow it.
- **Acceptance:** source-comment and doc injection fixtures flagged; a security-research doc *describing* injection is not a false positive.

### Component 3 — Command & execution-path analysis
- [x] Parse `package.json` scripts (pre/post-install), `Makefile`, shell scripts, build files, and `.github/workflows/*` for install-/build-time code execution, suspicious `curl|sh`, new network destinations, credential access.
- **Acceptance:** unsafe install/build hook + suspicious CI fixtures flagged with the executable path and the destination.

### Component 4 — MCP server & tool trust analysis
- [x] Parse MCP config (`.mcp.json`, `.cursor/mcp.json`, `mcp.json`, client configs): flag newly-registered/untrusted MCP servers, unpinned `npx -y`/`uvx` launchers, servers fetching remote code, and secrets embedded in MCP config.
- **Acceptance:** malicious MCP-config-change fixtures flagged; a pinned, known server is clean.

### Component 5 — Permission & sandbox configuration analysis
- [x] Detect permission-policy widening / sandbox weakening in agent configs (blanket allow-lists, disabled approvals, `--dangerously-*` flags, expanded tool scopes, disabled security checks).
- **Acceptance:** permission-escalation fixtures flagged with the before→after delta.

### Component 6 — Encoded-content & obfuscation analysis
- [x] Detect concealed instructions: hidden/bidirectional Unicode, zero-width chars, base64/hex/rot blobs that decode to instruction-like text, HTML/Markdown comment hiding, homoglyphs.
- **Acceptance:** encoded-instruction fixtures flagged (decoded conceptually, not executed); ordinary base64 assets not over-flagged.

### Component 7 — Cross-file PR attack-chain correlation
- [x] Build a graph linking: untrusted content → agent-consumption entry point → requested action → executable script → tool permission → sensitive resource → network destination → security control.
- [x] Emit **attack-chain findings** combining individually-low-risk changes; each finding states entry point, suspicious change, affected workflow, trust boundary, enabled action, file/line refs, confidence + **limitations**, remediation.
- **Acceptance:** a multi-file chain fixture (e.g. README injection → new npm postinstall → exfil URL) produces one correlated finding with the full path; unrelated benign changes do not chain.

### Safe analysis invariants (§D)
- [x] Passive by default: never execute untrusted instructions/hooks/install scripts/MCP servers. Any dynamic validation is opt-in, in a disposable sandbox with no prod creds, restricted FS/network, explicit authorization.
- [x] Secret canaries never appear in reports or external-model requests (reuse `internal/redact` + the canary test).

### CLI, reporting & integration (§G)
- [ ] Dedicated `trishul agent-security scan .` / `pr --base main` commands. _(Deferred: the CLI is a separate Go module that can't import `internal/agentsec`; lands with the CLI↔engine module-merge. Agent-security already runs inside every `trishul scan`.)_
- [x] Findings via CLI (rendered) + JSON + **SARIF** (check_id rule + trust-boundary + partialFingerprint); mapped to CWE-77/94/829/506/798. _(GitHub PR annotations + MCP tools: with PR mode / the module-merge.)_
- [x] Folded into the normal scan pipeline as a built-in, dependency-free analyzer set (runs read-only, no external LLM required).

### Benchmark (§F)
- [x] `testdata/agentsec/benchmark/` paired benign + malicious PR fixtures (incl. the hard security-research false-positive case) + a precision/recall/FP benchmark test. Measured recall 1.0 / precision 1.0 / 0 FP on this corpus; thresholds pinned at the measured values (not invented), limitations documented (small clean corpus, not a borderline stress test).

### Definition of done (§H)
- [x] Components parse configs structurally; attack chains carry verifiable evidence (AGENT-CHAIN-001 e2e-tested); no untrusted code executed (passive); secret canaries never leak (redaction + tests); **measured** malicious-vs-benign accuracy via the benchmark; docs state limitations. _(GitHub PR annotations + the dedicated CLI command remain, gated on the module-merge.)_
