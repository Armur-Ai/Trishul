#!/usr/bin/env bash
# Build trishul-app for linux/amd64 and roll it out to the armur.ai VM.
#   ./deploy/trishul-app/deploy.sh            (host defaults to "algoroq")
# Secrets live only on the VM in /etc/trishul-app (key.pem, webhook-secret,
# stats-token, env). Rollback: sudo mv /opt/trishul-app/trishul-app.prev /opt/trishul-app/trishul-app && sudo systemctl restart trishul-app
set -euo pipefail
HOST="${1:-algoroq}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VER="$(git -C "$ROOT" describe --tags --always --dirty)"
OUT="$(mktemp -d)/trishul-app"
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=$VER" -o "$OUT" ./cmd/trishul-app)
scp -q "$OUT" "$ROOT/deploy/trishul-app/trishul-app.service" "$HOST:/tmp/"
ssh "$HOST" 'set -e
  sudo install -d -m 755 /opt/trishul-app
  [ -f /opt/trishul-app/trishul-app ] && sudo cp /opt/trishul-app/trishul-app /opt/trishul-app/trishul-app.prev || true
  sudo install -m 755 /tmp/trishul-app /opt/trishul-app/trishul-app.new
  sudo mv /opt/trishul-app/trishul-app.new /opt/trishul-app/trishul-app
  sudo install -m 644 /tmp/trishul-app.service /etc/systemd/system/trishul-app.service
  rm -f /tmp/trishul-app /tmp/trishul-app.service
  sudo systemctl daemon-reload
  if [ -f /etc/trishul-app/env ]; then sudo systemctl enable --now trishul-app && sudo systemctl restart trishul-app; fi
  sleep 4; curl -fsS http://127.0.0.1:4610/healthz || sudo journalctl -u trishul-app -n 30 --no-pager'
echo "deployed $VER to $HOST"
