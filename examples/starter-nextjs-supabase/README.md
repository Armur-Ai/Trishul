# trishul-starter-nextjs-supabase

A minimal Next.js + Supabase starter pre-wired with **Trishul** security:

- `.github/workflows/trishul.yml` — the PR gate (runs in *your* CI; your code never leaves your environment).
- `.trishul.yml` — gate policy (blocks new critical/high).
- `supabase/migrations/` — a schema with Row Level Security correctly enabled.
- Run `trishul init claude` to also guard your AI agent's edits in real time.

[![Trishul](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/OWNER/REPO/main/.trishul/badge.json)](https://github.com/OWNER/REPO/security/code-scanning)

## Use it

```bash
# scan locally
npx trishul-cli scan .
# or install the agent guard
npx trishul-cli init claude
```

> This directory is a **template**. The owner publishes it as the public repo
> `Armur-Ai/trishul-starter-nextjs-supabase` (a D-HUMAN step); nothing here is
> pushed automatically.
