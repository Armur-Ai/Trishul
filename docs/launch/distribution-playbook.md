# Distribution playbook: getting Trishul onto every PR

The adoption loop mirrors Codecov's: **free for public repos → a PR comment that every contributor and reviewer sees → a README badge → a required check that sticks.** Trishul's edge is that it catches what generic SAST can't (agent-instruction attacks, MCP trust, the Vibe Top 10), so lead with that wedge, not with "another scanner".

## Shipped

- [x] `trishul-ci`: hermetic, diff-aware gate (only new findings), baseline file, SARIF, comment markdown
- [x] GitHub Action: sha256-verified install, PR diff mode, single edited comment, non-blocking by default
- [x] GitHub App: zero-YAML org install, check runs plus annotations, single comment, badge, stats/retention endpoint
- [x] `trishul init github --pr`: one command to adopt
- [x] Badge: `https://armur.ai/trishul-app/badge/OWNER/REPO.svg`

## Launch checklist (owner: Armur; needs a human decision)

1. **Tag `v0.2.0`.** The Action and `trishul init github` pin to it. Verify that the release contains the `trishul-ci_*` archives and `checksums.txt`.
2. **Dogfood for 1–2 weeks** on Armur-Ai repos (the App is private to the org at first). Watch `/stats` and the false-positive rate on real PRs.
3. **Make the App public:** GitHub → Armur-Ai → Settings → Developer settings → GitHub Apps → Trishul → Advanced → *Make public*.
4. **List on GitHub Marketplace**, both the Action (release with "Publish to Marketplace") and the App (free plan). Copy is below.
5. **"State of MCP Security" report:** publish only after private disclosure windows close (draft kept outside this repo).
6. **Get listed** on awesome-mcp-servers, awesome-claude-code, awesome-cursorrules and the Supabase community tools pages, with the badge plus a one-line value prop.
7. **Templates:** offer PRs adding the workflow to AI starter templates *whose maintainers opt in*. Don't open unsolicited bot PRs.
8. **Track** weekly: installs, active repos (7d), comments, 30-day retention, and uninstalls. Treat retention below 60% as a noise problem first.

## Marketplace copy (draft)

**Name:** Trishul PR Security Gate
**Tagline:** Security review for AI-written code. Only flags what each PR adds.

**Description:**
AI coding agents write a big share of today's PRs, and they repeat the same mistakes: Supabase tables without row-level security, service-role keys in client bundles, webhooks without signature checks, hallucinated packages. They also read your repo, so a PR can smuggle instructions into `CLAUDE.md`, `.cursorrules` or an MCP config that your agent will later follow.

Trishul checks every pull request for these issues and reports **only what that PR introduces**:

- 🔱 **AI agent supply-chain security:** prompt injection in agent instruction files, risky MCP servers, over-broad agent permissions, and fetch-and-run install hooks, correlated into attack chains.
- 🧪 **The Vibe Top 10:** missing authorization/IDOR, exposed data rules (Supabase/Firebase), client-side secrets, unverified webhooks, missing rate limits, unsafe LLM integrations, dependency provenance.
- 🤫 **Low noise:** diffed against the merge base, test fixtures ignored, a baseline file for accepted findings, one comment edited in place.
- 🔒 **Safe:** read-only and never executes your code. Open source (MIT).

Free for public and private repositories during the beta.
