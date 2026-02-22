#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/revenix-agent"
CONTAINER_NAME="revenix-core-agent"
IMAGE_NAME="revenix-core-agent:linux-amd64"
FIREWALL_CONTAINER_NAME="revenix-firewall-agent"
FIREWALL_IMAGE_NAME="revenix-firewall-agent:linux-amd64"

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
  --firewall-container-name NAME   Firewall container name (default: revenix-firewall-agent)
  --firewall-image-name NAME:TAG   Firewall image name (default: revenix-firewall-agent:linux-amd64)
  --help                  Show help
EOF
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Run as root (example: sudo ./start-agent.sh)."
  fi
}

is_truthy() {
  case "${1,,}" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

read_env_key() {
  local file="$1"
  local key="$2"
  local line
  line="$(grep -E "^${key}=" "$file" | head -n 1 || true)"
  printf '%s' "${line#*=}"
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
    --firewall-container-name)
      FIREWALL_CONTAINER_NAME="${2:-}"
      shift 2
      ;;
    --firewall-image-name)
      FIREWALL_IMAGE_NAME="${2:-}"
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

firewall_sync_enabled="$(read_env_key "$ENV_FILE" "FIREWALL_SYNC_ENABLED")"
if [[ -z "$firewall_sync_enabled" ]]; then
  firewall_sync_enabled="true"
fi

if is_truthy "$firewall_sync_enabled"; then
  if docker ps -a --format '{{.Names}}' | grep -Fxq "$FIREWALL_CONTAINER_NAME"; then
    docker rm -f "$FIREWALL_CONTAINER_NAME" >/dev/null 2>&1 || true
  fi

  if docker image inspect "$FIREWALL_IMAGE_NAME" >/dev/null 2>&1; then
    docker run -d \
      --name "$FIREWALL_CONTAINER_NAME" \
      --network host \
      --restart unless-stopped \
      --cap-add NET_ADMIN \
      --cap-add NET_RAW \
      --env-file "$ENV_FILE" \
      "$FIREWALL_IMAGE_NAME" >/dev/null
    printf 'Started %s\n' "$FIREWALL_CONTAINER_NAME"
  else
    printf 'WARNING: firewall image not found (%s); core started without firewall sync.\n' "$FIREWALL_IMAGE_NAME" >&2
  fi
else
  if docker ps -a --format '{{.Names}}' | grep -Fxq "$FIREWALL_CONTAINER_NAME"; then
    docker rm -f "$FIREWALL_CONTAINER_NAME" >/dev/null 2>&1 || true
  fi
  printf 'Firewall sync disabled by FIREWALL_SYNC_ENABLED=%s\n' "$firewall_sync_enabled"
fi

printf 'Started %s\n' "$CONTAINER_NAME"
