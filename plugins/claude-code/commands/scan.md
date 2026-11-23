---
description: Scan the current workspace for security vulnerabilities with Trishul (local, offline)
allowed-tools: Bash(trishul:*)
---

Run a Trishul security scan over the workspace and summarize what it finds.

Target: `$ARGUMENTS` (defaults to the current directory when empty).

!`trishul scan "${ARGUMENTS:-.}"`

Review the scanner output above and report back:

- The high and critical findings first, each with its file, line, and rule ID.
- A one-line explanation of the risk for each, and the suggested fix.
- A short overall verdict (safe to proceed / needs attention).

Everything Trishul does here is local and offline — it only reads files, never
executes them, and nothing leaves this machine.
