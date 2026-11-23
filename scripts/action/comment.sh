#!/usr/bin/env bash
# Creates or updates Trishul's single PR comment (found by its marker).
#   MODE=auto   comment only when there are new findings, or to update an
#               earlier Trishul comment (so a fixed PR flips to "all clear")
#   MODE=always always create/update
set -euo pipefail
: "${PR_NUMBER:?}" "${REPO:?}" "${BODY_FILE:?}" "${NEW_COUNT:=0}" "${MODE:=auto}"
MARKER='<!-- trishul-pr-gate -->'

existing=$(gh api --paginate "repos/$REPO/issues/$PR_NUMBER/comments" \
  --jq ".[] | select(.body | startswith(\"$MARKER\")) | .id" 2>/dev/null | head -n1 || true)

if [[ -n "$existing" ]]; then
  gh api -X PATCH "repos/$REPO/issues/comments/$existing" -F "body=@$BODY_FILE" >/dev/null
  echo "Updated Trishul comment $existing"
elif [[ "$MODE" == "always" || "$NEW_COUNT" != "0" ]]; then
  gh api -X POST "repos/$REPO/issues/$PR_NUMBER/comments" -F "body=@$BODY_FILE" >/dev/null
  echo "Posted Trishul comment"
else
  echo "No new findings and no previous comment; staying quiet."
fi
