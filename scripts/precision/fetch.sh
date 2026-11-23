#!/usr/bin/env bash
# fetch.sh — shallow-clone the precision corpus at its pinned SHAs into a cache
# directory (P0.1). The corpus is UNTRUSTED code we only ever read and scan, so
# this script is deliberately defensive:
#
#   - symlinks are disabled (core.symlinks=false) so a repo can't plant a link
#     that escapes the cache;
#   - Git LFS smudging is disabled so large binaries are not pulled or run;
#   - a 2 MB blob size filter keeps huge blobs out;
#   - nothing from a cloned repo is ever executed, sourced, or built here.
#
# Usage: fetch.sh <corpus.yaml> <cache-dir>
set -euo pipefail

CORPUS="${1:-testdata/precision/corpus.yaml}"
CACHE="${2:-.precision-cache}"

if ! command -v git >/dev/null 2>&1; then
  echo "fetch.sh: git is required" >&2
  exit 1
fi
mkdir -p "$CACHE"

# Minimal YAML reader: pull "repo:" / "sha:" pairs in document order. Good enough
# for the flat corpus.yaml shape (repos: list of {repo, sha, note}).
repo=""
sha=""
clone_one() {
  [ -z "$repo" ] && return 0
  [ -z "$sha" ] && { echo "fetch.sh: $repo has no sha; skipping" >&2; return 0; }
  # Normalize owner/name to a full GitHub URL.
  url="$repo"
  case "$url" in
    http*://*|git@*) : ;;
    */*) url="https://github.com/$url" ;;
  esac
  dir="$CACHE/$(printf '%s' "$repo" | sed -e 's#\.git$##' -e 's#https://github.com/##' -e 's#git@github.com:##' -e 's#[/:]#__#g')"
  if [ -d "$dir/.git" ]; then
    echo "have $repo"
  else
    echo "clone $repo @ $sha"
    GIT_LFS_SKIP_SMUDGE=1 git clone \
      --no-checkout --filter=blob:limit=2m \
      -c core.symlinks=false -c advice.detachedHead=false \
      "$url" "$dir" 2>/dev/null || { echo "fetch.sh: clone failed: $repo" >&2; repo=""; sha=""; return 0; }
  fi
  # Fetch and check out exactly the pinned SHA (shallow where possible).
  git -C "$dir" -c core.symlinks=false fetch --filter=blob:limit=2m --depth 1 origin "$sha" 2>/dev/null || \
    git -C "$dir" -c core.symlinks=false fetch origin 2>/dev/null || true
  GIT_LFS_SKIP_SMUDGE=1 git -C "$dir" -c core.symlinks=false checkout -q "$sha" 2>/dev/null || \
    echo "fetch.sh: could not checkout $sha in $repo" >&2
  repo=""
  sha=""
}

while IFS= read -r line; do
  case "$line" in
    *"- repo:"*|*"-repo:"*) clone_one; repo="$(printf '%s' "$line" | sed -E 's/.*repo:[[:space:]]*//; s/[[:space:]]*$//')" ;;
    *"sha:"*)               sha="$(printf '%s' "$line" | sed -E 's/.*sha:[[:space:]]*//; s/[[:space:]]*$//')" ;;
  esac
done < "$CORPUS"
clone_one

echo "corpus cached in $CACHE"
