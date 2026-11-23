#!/usr/bin/env bash
# Installs trishul-ci for the GitHub Action.
#
# 1. If a release matching the requested version exists, download the
#    trishul-ci archive and verify its sha256 against the release's
#    checksums.txt before extracting. Never pipes a remote script to a shell.
# 2. Otherwise build from the action's own source (ACTION_PATH), which is
#    pinned to exactly the ref the workflow referenced (Go modules verified by
#    go.sum).
set -euo pipefail

REPO="Armur-Ai/Trishul"
VERSION="${TRISHUL_VERSION:-}"
ACTION_REF="${ACTION_REF:-}"
DEST="${RUNNER_TEMP:-/tmp}/trishul-bin"
mkdir -p "$DEST"

# Default the version to the action ref when it is a release tag (vX.Y.Z), so
# `uses: Armur-Ai/Trishul@v0.2.0` runs trishul-ci 0.2.0.
if [[ -z "$VERSION" && "$ACTION_REF" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  VERSION="$ACTION_REF"
fi
VERSION="${VERSION#v}"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "::error::unsupported arch $(uname -m)"; exit 1 ;;
esac
case "$os" in
  linux|darwin) ext=tar.gz ;;
  mingw*|msys*|cygwin*) os=windows; ext=zip ;;
esac

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

try_release() {
  [[ -z "$VERSION" ]] && return 1
  local name="trishul-ci_${VERSION}_${os}_${arch}.${ext}"
  local base="https://github.com/${REPO}/releases/download/v${VERSION}"
  local tmp; tmp=$(mktemp -d)
  curl -fsSL --retry 3 -o "$tmp/$name" "$base/$name" 2>/dev/null || return 1
  curl -fsSL --retry 3 -o "$tmp/checksums.txt" "$base/checksums.txt" || { echo "::error::release has no checksums.txt"; exit 1; }
  local want; want=$(awk -v n="$name" '$2==n {print $1}' "$tmp/checksums.txt")
  local got; got=$(sha256 "$tmp/$name")
  if [[ -z "$want" || "$want" != "$got" ]]; then
    echo "::error::checksum mismatch for $name (want '$want', got '$got'); refusing to run"
    exit 1
  fi
  if [[ "$ext" == zip ]]; then unzip -q -o "$tmp/$name" -d "$DEST"; else tar -xzf "$tmp/$name" -C "$DEST"; fi
  echo "Installed trishul-ci v${VERSION} (sha256 verified)"
}

build_source() {
  echo "No trishul-ci release for '${VERSION:-<unset>}'; building from action source at ${ACTION_REF:-HEAD}"
  if ! command -v go >/dev/null; then
    echo "::error::Go is required to build trishul-ci from source. Pin the action to a release tag (e.g. @v0.2.0) or add actions/setup-go."
    exit 1
  fi
  (cd "$ACTION_PATH" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${ACTION_REF:-source}" -o "$DEST/trishul-ci" ./cmd/trishul-ci)
}

try_release || build_source
"$DEST/trishul-ci" --version
echo "$DEST" >> "$GITHUB_PATH"
