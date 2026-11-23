# Precision labeling protocol

This is how findings are labeled for the precision harness (plan P0). The goal is
a trustworthy per-rule precision number, so the labeling process is explicit and
reproducible.

## Verdict classes

Each labeled finding gets exactly one verdict:

| Verdict | Meaning |
|---------|---------|
| `tp` | A real, actionable security issue a maintainer should fix. |
| `tp_benign` | Technically correct detection, but not actionable in context (e.g. a real secret that is a public test key). Counts as **correct** for precision. |
| `fp` | The finding is wrong — the condition it claims does not hold. |
| `unclear` | Cannot be decided without more context. **Excluded** from precision. |

Precision is `(tp + tp_benign) / (tp + tp_benign + fp)`. `unclear` is never
counted — if a rule has many `unclear` labels, that is itself a signal the rule's
message or evidence is too vague.

## Label record (`labels.jsonl`)

One JSON object per line:

```json
{"fingerprint_v2":"<hex>","repo":"owner/name","sha":"<commit>","rule_id":"AGENT-EXEC-002","path":"src/x.go","line":42,"verdict":"fp","reason":"the hook only runs on a trusted local path","reviewer":"alice","date":"2026-11-23"}
```

- `fingerprint_v2` is the finding's identity (see `internal/findings`); it is how
  `trishul-bench` joins a re-scan back to its label.
- `reason` is **required** and must describe the evidence, not restate the
  verdict ("the policy is applied in `middleware/auth.ts:10`", not "false
  positive").
- Secret values are **never** copied into `reason` — refer to them, don't paste
  them.

## Two-reviewer rule

1. Every finding sampled for labeling is reviewed by **two** reviewers
   independently; neither sees the other's verdict first.
2. If they agree, that verdict stands.
3. If they disagree, a third reviewer adjudicates, OR the two discuss and record
   a joint verdict with a reason that names the deciding evidence. A finding that
   cannot be resolved is labeled `unclear`.
4. Values (secrets, tokens, PII) are referenced, never copied into the label.

## Sampling

- Every rule that fired in the corpus scan must reach **≥ 5 decided labels**, or
  be explicitly marked "insufficient data".
- Under-sampled rules are labeled first — `trishul-bench` orders the queue by
  fewest labels (information gain), then by severity.
- When adding labels for a rule with fewer than 3, sample findings at random with
  a fixed seed so the set is reproducible.

## Running the harness

```sh
# 1. fetch the pinned corpus (read-only, never executed)
scripts/precision/fetch.sh testdata/precision/corpus.yaml .precision-cache

# 2. scan a cached repo and see which findings still need labels
trishul-bench scan --dir .precision-cache/<owner__name> --labels testdata/precision/labels.jsonl

# 3. report per-rule precision + Wilson 95% CI
trishul-bench report --labels testdata/precision/labels.jsonl --md docs/rules/precision.md
```
