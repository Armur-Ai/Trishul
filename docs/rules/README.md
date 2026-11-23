# Rule catalog

54 rules. Generated from the rule catalog by `trishul-rulesdoc`; do not edit by hand.

| ID | Title | Severity | Maturity |
| --- | --- | --- | --- |
| [AGENT-CHAIN-001](AGENT-CHAIN-001.md) | Cross-file agent attack chain: untrusted content + an enabled execution/permission path | CRITICAL | stable |
| [AGENT-EXEC-001](AGENT-EXEC-001.md) | Risky install-lifecycle script in package.json | HIGH | stable |
| [AGENT-EXEC-002](AGENT-EXEC-002.md) | Risky install/build script execution path | HIGH | stable |
| [AGENT-EXEC-003](AGENT-EXEC-003.md) | Risky CI workflow execution path | HIGH | stable |
| [AGENT-INJ-001](AGENT-INJ-001.md) | Prompt-injection directive in source-code comment | MEDIUM | beta |
| [AGENT-INJ-002](AGENT-INJ-002.md) | Prompt-injection directive in documentation or fixture | MEDIUM | beta |
| [AGENT-INJ-003](AGENT-INJ-003.md) | Prompt-injection directive in issue/PR template | MEDIUM | beta |
| [AGENT-INSTR-001](AGENT-INSTR-001.md) | Instruction-override attempt in agent instruction file | MEDIUM | stable |
| [AGENT-INSTR-002](AGENT-INSTR-002.md) | System/developer authority impersonation in instruction file | MEDIUM | stable |
| [AGENT-INSTR-003](AGENT-INSTR-003.md) | Agent role or authority escalation directive | MEDIUM | stable |
| [AGENT-INSTR-004](AGENT-INSTR-004.md) | Sensitive-action directive in agent instruction file | HIGH | stable |
| [AGENT-MCP-001](AGENT-MCP-001.md) | MCP server launched via unpinned package runner | HIGH | stable |
| [AGENT-MCP-002](AGENT-MCP-002.md) | MCP server fetches and runs remote code | HIGH | stable |
| [AGENT-MCP-003](AGENT-MCP-003.md) | Secret embedded in MCP server config | HIGH | stable |
| [AGENT-MCP-004](AGENT-MCP-004.md) | Remote MCP server configured — review its trust | MEDIUM | beta |
| [AGENT-OBFS-001](AGENT-OBFS-001.md) | Hidden or bidirectional Unicode concealing text | MEDIUM | stable |
| [AGENT-OBFS-002](AGENT-OBFS-002.md) | Homoglyph/confusable disguising a security keyword | MEDIUM | stable |
| [AGENT-OBFS-003](AGENT-OBFS-003.md) | Encoded blob decodes to instruction-like text | HIGH | stable |
| [AGENT-OBFS-004](AGENT-OBFS-004.md) | Directive hidden in a comment invisible when rendered | HIGH | stable |
| [AGENT-PERM-001](AGENT-PERM-001.md) | Blanket allow-all tool permissions | HIGH | stable |
| [AGENT-PERM-002](AGENT-PERM-002.md) | Agent approval/confirmation disabled | HIGH | stable |
| [AGENT-PERM-003](AGENT-PERM-003.md) | Dangerous permission/sandbox-bypass flag | HIGH | stable |
| [AGENT-PERM-004](AGENT-PERM-004.md) | Security check disabled | MEDIUM | stable |
| [CLIENT-SECRET-001](CLIENT-SECRET-001.md) | Secret assigned to a client-exposed environment variable | HIGH | stable |
| [CLIENT-SECRET-002](CLIENT-SECRET-002.md) | Committed .env file contains a secret | HIGH | stable |
| [CLIENT-SECRET-003](CLIENT-SECRET-003.md) | Privileged secret in a client-side file | CRITICAL | stable |
| [FIREBASE-001](FIREBASE-001.md) | Firestore rule allows world read and write | CRITICAL | stable |
| [FIREBASE-002](FIREBASE-002.md) | Firestore/Storage rule allows any authenticated user without ownership check | HIGH | stable |
| [FIREBASE-003](FIREBASE-003.md) | Cloud Storage rule grants an unconditional allow | HIGH | stable |
| [FIREBASE-004](FIREBASE-004.md) | Broad {document=**} catch-all with a permissive allow | MEDIUM | stable |
| [SUPABASE-RLS-001](SUPABASE-RLS-001.md) | Table created without row-level security | HIGH | stable |
| [SUPABASE-RLS-002](SUPABASE-RLS-002.md) | RLS policy with an always-true predicate (effectively public) | CRITICAL | stable |
| [SUPABASE-RLS-003](SUPABASE-RLS-003.md) | RLS policy grants write/ALL to the anon role | HIGH | stable |
| [SUPABASE-RLS-004](SUPABASE-RLS-004.md) | SECURITY DEFINER function without a pinned search_path | HIGH | stable |
| [SUPABASE-RLS-005](SUPABASE-RLS-005.md) | Public storage bucket | HIGH | stable |
| [VIBE-ABUSE-001](VIBE-ABUSE-001.md) | Auth or LLM endpoint without rate limiting | MEDIUM | stable |
| [VIBE-ABUSE-002](VIBE-ABUSE-002.md) | File upload handler without a size limit | MEDIUM | stable |
| [VIBE-ABUSE-003](VIBE-ABUSE-003.md) | Unvalidated req.body spread into a database write | LOW | stable |
| [VIBE-AUTHZ-001](VIBE-AUTHZ-001.md) | Unauthenticated data route (missing authorization) | HIGH | stable |
| [VIBE-AUTHZ-002](VIBE-AUTHZ-002.md) | IDOR: record looked up by request id without owner scoping | HIGH | stable |
| [VIBE-DEP-001](VIBE-DEP-001.md) | Dependency sourced from a non-registry location | MEDIUM | stable |
| [VIBE-DEP-002](VIBE-DEP-002.md) | Unpinned dependency with no lockfile | LOW | stable |
| [VIBE-DEP-003](VIBE-DEP-003.md) | Overrides/resolutions repoint a package to a non-registry source | MEDIUM | stable |
| [VIBE-LLM-001](VIBE-LLM-001.md) | Untrusted input interpolated into an LLM prompt (prompt injection) | HIGH | stable |
| [VIBE-LLM-002](VIBE-LLM-002.md) | LLM output flows into a dangerous sink | HIGH | stable |
| [VIBE-LLM-003](VIBE-LLM-003.md) | Provider API key used in client-side code | CRITICAL | stable |
| [VIBE-PLACEHOLDER-001](VIBE-PLACEHOLDER-001.md) | Hardcoded placeholder or weak signing secret | HIGH | stable |
| [VIBE-PLACEHOLDER-002](VIBE-PLACEHOLDER-002.md) | Default or well-known credentials | HIGH | stable |
| [VIBE-PLACEHOLDER-003](VIBE-PLACEHOLDER-003.md) | Disabled TLS/certificate verification | HIGH | stable |
| [VIBE-PLACEHOLDER-004](VIBE-PLACEHOLDER-004.md) | Wildcard CORS origin combined with credentials | HIGH | stable |
| [VIBE-PLACEHOLDER-005](VIBE-PLACEHOLDER-005.md) | Debug mode enabled | MEDIUM | stable |
| [VIBE-PLACEHOLDER-006](VIBE-PLACEHOLDER-006.md) | Security-related TODO/FIXME marker | LOW | stable |
| [VIBE-WEBHOOK-001](VIBE-WEBHOOK-001.md) | Unverified provider webhook handler | HIGH | stable |
| [VIBE-WEBHOOK-002](VIBE-WEBHOOK-002.md) | Client-trusted payment/access value from request body | HIGH | stable |
