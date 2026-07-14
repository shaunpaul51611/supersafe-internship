#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/shaunpaul51611/supersafe-internship.git}"
APP_DIR="${APP_DIR:-$HOME/quantum-safe-share}"
PUBLIC_PORT="${SECURE_SHARE_PUBLIC_PORT:-8000}"

echo "Preparing Oracle Cloud server for Quantum Safe Share..."

if ! command -v sudo >/dev/null 2>&1; then
  echo "This setup script expects sudo to be available." >&2
  exit 1
fi

if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y ca-certificates curl git
else
  echo "This script is written for Ubuntu/Debian images. Create the Oracle VM with Ubuntu 24.04 or newer." >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sudo sh
  sudo usermod -aG docker "$USER" || true
fi

if [ -d "$APP_DIR/.git" ]; then
  git -C "$APP_DIR" pull --ff-only
else
  git clone "$REPO_URL" "$APP_DIR"
fi

cd "$APP_DIR"

if [ ! -f .env ]; then
  cp .env.example .env
fi

SECURE_SHARE_PUBLIC_PORT="$PUBLIC_PORT" docker compose up -d --build

echo "Waiting for local health check..."
for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${PUBLIC_PORT}/health" >/dev/null; then
    echo "Server is healthy at http://127.0.0.1:${PUBLIC_PORT}/health"
    docker compose ps
    cat <<EOF

Next steps:
1. In Oracle Cloud, allow ingress TCP ports 80 and 443 in the VM subnet security list.
2. Point your domain/subdomain A record to this VM public IP.
3. Install Caddy and use deploy/Caddyfile.example for HTTPS.
4. Set the desktop app to SECURE_SHARE_SERVER_URL=https://your-domain.example

EOF
    exit 0
  fi
  sleep 2
done

echo "The container started, but /health did not answer in time. Check logs with:" >&2
echo "docker compose logs --tail=100 secure-share-server" >&2
exit 1
