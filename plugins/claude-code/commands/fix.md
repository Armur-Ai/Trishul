---
description: Generate a minimal code patch for a Trishul security finding
argument-hint: <finding-id>
allowed-tools: Bash(trishul:*)
---

Generate a minimal, behavior-preserving patch for a Trishul security finding.

Finding to fix: `$ARGUMENTS`

!`trishul fix "$ARGUMENTS"`

Review the proposed patch above. Then:

- Explain, in one or two lines, what the fix changes and why it closes the issue.
- If it looks correct, apply it with `trishul fix "$ARGUMENTS" --apply` (or make the
  edit yourself), then re-run `/trishul:scan` on the touched file to confirm the
  finding is gone.
- If the patch is wrong or risky, say so and propose a safer change instead.

AI-powered fix generation needs `ANTHROPIC_API_KEY` or a local Ollama instance;
set one up with `trishul config set anthropic-api-key <your-key>`. The patch is
generated and applied locally.
