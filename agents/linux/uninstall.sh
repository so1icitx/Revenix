#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/revenix-agent"
CONTAINER_NAME="revenix-core-agent"
IMAGE_NAME="revenix-core-agent:linux-amd64"
REMOVE_IMAGE="false"
PURGE_FILES="false"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: sudo ./uninstall.sh [options]

Options:
  --install-dir PATH      Install directory (default: /opt/revenix-agent)
  --container-name NAME   Container name (default: revenix-core-agent)
  --image-name NAME:TAG   Image name (default: revenix-core-agent:linux-amd64)
  --remove-image          Remove docker image too
  --purge-files           Remove install directory too
  --help                  Show help
EOF
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Run as root (example: sudo ./uninstall.sh)."
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
    --remove-image)
      REMOVE_IMAGE="true"
      shift
      ;;
    --purge-files)
      PURGE_FILES="true"
      shift
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

if docker ps -a --format '{{.Names}}' | grep -Fxq "$CONTAINER_NAME"; then
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
fi

if [[ "$REMOVE_IMAGE" == "true" ]]; then
  docker image rm -f "$IMAGE_NAME" >/dev/null 2>&1 || true
fi

if [[ "$PURGE_FILES" == "true" && -d "$INSTALL_DIR" ]]; then
  rm -rf "$INSTALL_DIR"
fi

printf 'Revenix Linux agent removed.\n'

