# Authoring a built-in analyzer

Trishul's built-in analyzers are small, dependency-free, read-only detectors
that run on **every** scan — no external binary, no Docker, no network. This is
how the Vibe Top 10 analyzers (placeholder-security, route-authorization,
webhook-verification, abuse-controls, llm-integration, dependency-provenance)
and the Supabase/Firebase rules analyzers are built. This guide shows how to add
one.

## 1. Write the analyzer

Create one new file under `internal/tools/` (package `internal`). Expose a single
entry point:

```go
// RunMyThing scans dir (read-only) and returns findings under one category.
func RunMyThing(dir string) (map[string]interface{}, error) {
    // walk with filepath.WalkDir; skip node_modules/.git/dist/build/.next/vendor;
    // cap files at ~2 MiB; only read the extensions you understand.
    // Build flat finding maps and return them under the right category key.
}
```

Return shape — a map whose key is the output **category** and whose value is a
`[]interface{}` of flat finding maps:

```go
return map[string]interface{}{
    utils.VIBE_SECURITY: []interface{}{
        map[string]interface{}{
            "path":        rel,            // repo-relative path
            "line":        line,           // int
            "message":     "...",          // what and why
            "severity":    "HIGH",         // CRITICAL|HIGH|MEDIUM|LOW
            "check_id":    "VIBE-MYTHING-001",
            "cwe":         "CWE-123",
            "confidence":  "MEDIUM",        // be honest about heuristics
            "remediation": "...",
        },
    },
}, nil
```

Pick the category that matches the finding:

| Constant | Use for |
|---|---|
| `utils.VIBE_SECURITY` | Vibe Top 10 application-logic issues |
| `utils.INFRA_SECURITY` | infrastructure / data-layer rules |
| `utils.SECRET_DETECTION` | secrets (always redact the value) |
| `utils.AGENT_SECURITY` | AI-agent supply-chain issues |

`internal/tools/supabase.go` and `internal/tools/placeholder.go` are good models.

## 2. The rules

- **Read-only.** Never execute, mutate, or write anything. Decode encoded blobs
  in-process for inspection only.
- **Redact secrets.** Never put a raw secret in a finding — use
  `redact.Mask` / `redact.Fingerprint` (see `internal/redact`). There is a test
  that asserts no raw value leaks; add one for your analyzer too.
- **Be conservative.** Prefer a miss to a false positive. Suppress on the obvious
  safe signals (an env/vault reference, a present guard, a lockfile, a test
  file), and set `confidence` honestly. A heuristic that can be wrong says so.
- **Be deterministic.** De-duplicate and sort findings (by path, line, check_id)
  so diffs are stable across runs.
- **Stay self-contained.** Prefix package-level identifiers to avoid collisions
  with sibling analyzers (the build/test gate will catch a clash).

## 3. Wire it in

Register the analyzer in `internal/tasks/tasks.go`, in
`buildSimpleScanRunnersNamed`, alongside the other built-ins:

```go
withTimeout("my-thing", func() toolResult {
    r, err := tools.RunMyThing(dirPath)
    return toolResult{"my-thing", r, err}
}),
```

and add its name to the `names` slice. That's all — it now runs on every scan,
and (if it emits a known category) surfaces in the CLI and in SARIF
automatically. A brand-new category needs a one-line surfacing in
`RunSimpleScan` / `RunSimpleScanLocal`, a SARIF block in `pkg/sarif/sarif.go`,
and a CLI renderer in `cli/cmd/scan.go` — see how `vibe_security` was added.

## 4. Test it

Add `internal/tools/mything_test.go` with `t.TempDir()` fixtures: a positive
case per check_id, a negative case that must stay clean, and an empty-dir case.
Assert the category key, the check_ids, and the finding shape. Build-gate every
commit:

```bash
go build ./... && go test ./internal/tools/ -count=1
```
