#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/revenix-agent"
CONTAINER_NAME="revenix-core-agent"
IMAGE_NAME="revenix-core-agent:linux-amd64"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: sudo ./start-agent.sh [options]

Options:
  --install-dir PATH      Install directory (default: /opt/revenix-agent)
  --container-name NAME   Container name (default: revenix-core-agent)
  --image-name NAME:TAG   Image name (default: revenix-core-agent:linux-amd64)
  --help                  Show help
EOF
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Run as root (example: sudo ./start-agent.sh)."
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-dir)
      INSTALL_DIR="${2:-}"
      shift 2
      ;;
    --container-name)
      CONTAINER_NAME="${2:-}"
      shift 2
      ;;
    --image-name)
      IMAGE_NAME="${2:-}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      die "Unknown option: $1 (use --help)"
      ;;
  esac
done

require_root
command -v docker >/dev/null 2>&1 || die "docker is not installed."
docker info >/dev/null 2>&1 || die "docker daemon is not reachable."
docker image inspect "$IMAGE_NAME" >/dev/null 2>&1 || die "Image $IMAGE_NAME not found."

ENV_FILE="$INSTALL_DIR/agent.env"
[[ -f "$ENV_FILE" ]] || die "Missing env file: $ENV_FILE"

if docker ps -a --format '{{.Names}}' | grep -Fxq "$CONTAINER_NAME"; then
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
fi

docker run -d \
  --name "$CONTAINER_NAME" \
  --network host \
  --restart unless-stopped \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --env-file "$ENV_FILE" \
  "$IMAGE_NAME" >/dev/null

printf 'Started %s\n' "$CONTAINER_NAME"

