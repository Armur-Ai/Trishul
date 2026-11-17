# The Vibe Top 10 — detection reference

Trishul organizes its findings around the **Vibe Top 10**: the security failure
modes that recur in AI-generated ("vibe-coded") applications. This page lists
what each built-in analyzer detects, the check IDs it emits, the category it
surfaces under, and how it holds down false positives.

All of these analyzers are **read-only and dependency-free**. They run on every
`trishul scan` (no external tool required), treat all scanned text as data, and
never emit a raw secret value — secrets are redacted to a masked preview plus a
stable fingerprint.

| Category in output | Meaning |
|---|---|
| `security_issues` | SAST findings (semgrep / gosec rules) |
| `secret_detection` | Secrets, including client-exposed keys (V01) |
| `infra_security` | Infrastructure & data-layer rules (Supabase V03, Firebase) |
| `vibe_security` | The dedicated Vibe analyzers below (V06–V09, provenance) |
| `agent_security` | AI Agent Supply-Chain Security (V10) — see [agent-security.md](agent-security.md) |

---

## V01 — Secrets shipped to the client

**Analyzer:** `client-secrets` → `secret_detection`.
Detects provider keys and privileged tokens that leak into client/browser
bundles.

| Check ID | What it flags |
|---|---|
| `CLIENT-SECRET-001` | A secret-shaped value assigned to a client-exposed env var (`NEXT_PUBLIC_`, `VITE_`, …) — inlined into the bundle at build time |
| `CLIENT-SECRET-002` | A committed `.env` file carrying a secret-shaped assignment |
| `CLIENT-SECRET-003` | A high-confidence privileged secret (Supabase `service_role` JWT, private key, `sk-`-style key) in a client-looking file |

Values are entropy-gated and always redacted. Prose and identifiers sit below
the entropy floor, which keeps the noise down.

## V03 — Open data layer

**Analyzer:** `supabase-rls` → `infra_security` (Firebase analyzer complements it).

| Check ID | What it flags |
|---|---|
| `SUPABASE-RLS-001` | A public table created with no row-level security policy |
| `SUPABASE-RLS-002` | An effectively-public policy predicate (`using (true)`) |
| `SUPABASE-RLS-003` | The `anon` role granted a sensitive operation |
| `SUPABASE-RLS-004` | A `SECURITY DEFINER` function with no pinned `search_path` |
| `FIREBASE-00x` | Firestore/Storage rules of `allow read, write: if true`, auth-only (no ownership) rules, and public buckets |

A rule locked with `if false`, or scoped by an ownership predicate
(`request.auth.uid == resource.data.ownerId`) or admin claim, is treated as safe.

## V06 — Placeholder / insecure-default security

**Analyzer:** `placeholder-security` → `vibe_security`.

| Check ID | What it flags |
|---|---|
| `VIBE-PLACEHOLDER-001` | Hardcoded JWT/session/signing secrets with placeholder values (the value is redacted) |
| `VIBE-PLACEHOLDER-002` | Default credentials (`admin`/`admin`, inline `user:pass@`) |
| `VIBE-PLACEHOLDER-003` | Disabled verification (`verify=False`, `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `InsecureSkipVerify: true`) |
| `VIBE-PLACEHOLDER-004` | Wildcard CORS combined with credentials |
| `VIBE-PLACEHOLDER-005` | Debug mode left on |
| `VIBE-PLACEHOLDER-006` | Security `TODO`/`FIXME`/`HACK` markers (informational) |

Values read from `process.env` / `os.environ` / a vault, commented-out lines, and
long high-entropy literals are suppressed. Test/mock/example files get lowered
confidence.

## V07 — Unverified webhooks & payment logic

**Analyzer:** `webhook-verification` → `vibe_security`.

| Check ID | What it flags |
|---|---|
| `VIBE-WEBHOOK-001` | A provider webhook handler (Stripe/Svix/Clerk/GitHub/Shopify/PayPal) that reads the raw body but never verifies the signature |
| `VIBE-WEBHOOK-002` | A payment/access handler trusting `amount`/`price`/`plan`/`role`/`isAdmin` from the request body |

001 fires only when the file reads the whole raw body **and** has no verify
indicator (`constructEvent`, HMAC compare, a provider signature header). 002 is
gated on a payment or access context token, so a plain route reading `req.body`
is clean.

## V08 — Missing abuse controls

**Analyzer:** `abuse-controls` → `vibe_security`.

| Check ID | What it flags |
|---|---|
| `VIBE-ABUSE-001` | Auth (login/signup/reset/OTP) or LLM-provider routes when no rate limiter exists anywhere in the project |
| `VIBE-ABUSE-002` | An upload handler with no size limit configured |
| `VIBE-ABUSE-003` | A mutating route spreading `req.body` into a DB write with no validation library |

001 is suppressed project-wide if any limiter
(`express-rate-limit`, `@upstash/ratelimit`, `slowapi`, …) is present. Health and
static routes are never flagged.

## V09 — Unsafe LLM integration

**Analyzer:** `llm-integration` → `vibe_security`.

| Check ID | What it flags |
|---|---|
| `VIBE-LLM-001` | Request-derived input concatenated/interpolated into a prompt or `messages` content (prompt-injection sink) |
| `VIBE-LLM-002` | An LLM completion flowing into `eval`/`Function`, `exec`/`child_process`, a SQL call, or `innerHTML`/`dangerouslySetInnerHTML` |
| `VIBE-LLM-003` | An OpenAI/Anthropic client constructed with an `apiKey` in client-side code (`"use client"`, `dangerouslyAllowBrowser: true`) |

Bounded taint propagation links indirect flows. Prompts built only from constant
strings, and model output merely displayed as text, are not flagged. The API key
value is never parsed or emitted.

## V04 — Hallucinated & risky dependencies

**Analyzer:** `dependency-provenance` → `vibe_security` (plus CVE lookup in the deep pass).

| Check ID | What it flags |
|---|---|
| `VIBE-DEP-001` | A dependency sourced from a non-registry location (`git`/`http`/`file:`/`github:`) that bypasses registry integrity |
| `VIBE-DEP-002` | An unpinned floating spec (`*`, `latest`) with no lockfile to pin it |
| `VIBE-DEP-003` | An `overrides`/`resolutions` entry repointing a known package to a non-registry source |

## V02 — Missing or client-only authorization

**Analyzer:** `route-authorization` → `vibe_security`.

| Check ID | What it flags |
|---|---|
| `VIBE-AUTHZ-001` | An API route/handler that reads or writes data with no visible session/auth check |
| `VIBE-AUTHZ-002` | An IDOR heuristic — a handler querying by a request-supplied id with no owner predicate |

A static heuristic, deliberately conservative: routes with a clear auth check,
and public/health routes, are not flagged. Confidence is reported honestly.

## V05 — String-built injection

Covered by the SAST pass (`security_issues`): command injection, XSS, `eval` of
request-derived data, and SQL injection (Python today).

## V10 — Poisoned agent context

The flagship **AI Agent Supply-Chain Security** capability. See
[agent-security.md](agent-security.md) for the threat model, the seven
components, and the cross-file attack-chain correlation (`AGENT-CHAIN-001`).

---

### Reporting & honesty

Every analyzer above reports only what it actually found. None of them executes
untrusted code, and none claims a system is compromised merely because suspicious
text exists. Findings carry a `confidence` field; a heuristic that can be wrong
says so. Output is deterministic (sorted, de-duplicated) so diffs are stable
across runs, and all findings are emitted to SARIF 2.1.0 for CI.
