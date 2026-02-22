#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

INSTALL_DIR="/opt/revenix-agent"
CONTAINER_NAME="revenix-core-agent"
IMAGE_NAME="revenix-core-agent:linux-amd64"
IMAGE_TAR="$SCRIPT_DIR/revenix-core-image.tar"
FIREWALL_CONTAINER_NAME="revenix-firewall-agent"
FIREWALL_IMAGE_NAME="revenix-firewall-agent:linux-amd64"
FIREWALL_IMAGE_TAR="$SCRIPT_DIR/revenix-firewall-image.tar"
ENV_SOURCE="$SCRIPT_DIR/agent.env"
ENV_TEMPLATE="$SCRIPT_DIR/agent.env.example"
SKIP_DOCKER_INSTALL="false"

API_URL_OVERRIDE=""
REDIS_URL_OVERRIDE=""
REDIS_PASSWORD_OVERRIDE=""
NETWORK_INTERFACE_OVERRIDE=""
PROMISCUOUS_MODE_OVERRIDE=""
FIREWALL_SYNC_ENABLED_OVERRIDE=""

log() {
  printf '%s\n' "$*"
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: sudo ./install.sh [options]

Options:
  --api-url URL                  Override API_URL
  --redis-url URL                Override REDIS_URL
  --redis-password VALUE         Override REDIS_PASSWORD
  --network-interface VALUE      Override NETWORK_INTERFACE
  --promiscuous-mode true|false  Override PROMISCUOUS_MODE
  --install-dir PATH             Install directory (default: /opt/revenix-agent)
  --container-name NAME          Container name (default: revenix-core-agent)
  --image-name NAME:TAG          Image name (default: revenix-core-agent:linux-amd64)
  --image-tar PATH               Path to image tar (default: ./revenix-core-image.tar)
  --firewall-container-name NAME Firewall container name (default: revenix-firewall-agent)
  --firewall-image-name NAME:TAG Firewall image name (default: revenix-firewall-agent:linux-amd64)
  --firewall-image-tar PATH      Firewall image tar (default: ./revenix-firewall-image.tar)
  --firewall-sync-enabled BOOL   Override FIREWALL_SYNC_ENABLED in agent.env
  --skip-docker-install          Fail if docker is missing instead of auto-installing it
  --help                         Show this help
EOF
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    die "Run as root (example: sudo ./install.sh)."
  fi
}

update_env_key() {
  local file="$1"
  local key="$2"
  local value="$3"
  local tmp
  tmp="$(mktemp)"
  awk -F= -v k="$key" -v v="$value" '
    BEGIN { updated = 0 }
    $1 == k { print k "=" v; updated = 1; next }
    { print $0 }
    END { if (updated == 0) print k "=" v }
  ' "$file" > "$tmp"
  mv "$tmp" "$file"
}

read_env_key() {
  local file="$1"
  local key="$2"
  local line
  line="$(grep -E "^${key}=" "$file" | head -n 1 || true)"
  printf '%s' "${line#*=}"
}

ensure_docker() {
  if command -v docker >/dev/null 2>&1; then
    :
  else
    if [[ "$SKIP_DOCKER_INSTALL" == "true" ]]; then
      die "docker is not installed."
    fi

    log "docker not found; installing automatically..."
    if command -v apt-get >/dev/null 2>&1; then
      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y docker.io
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y docker
    elif command -v yum >/dev/null 2>&1; then
      yum install -y docker
    else
      die "Unsupported distro for automatic docker install. Install docker and rerun."
    fi
  fi

  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now docker >/dev/null 2>&1 || true
    systemctl start docker >/dev/null 2>&1 || true
  fi

  command -v docker >/dev/null 2>&1 || die "docker command is still missing."
  docker info >/dev/null 2>&1 || die "docker daemon is not reachable."
}

validate_url_placeholders() {
  local api_url="$1"
  local redis_url="$2"
  [[ -n "$api_url" ]] || die "API_URL is empty."
  [[ -n "$redis_url" ]] || die "REDIS_URL is empty."
  [[ "$api_url" != *"YOUR-MAIN-SERVER"* ]] || die "API_URL still has placeholder value."
  [[ "$redis_url" != *"YOUR-MAIN-SERVER"* ]] || die "REDIS_URL still has placeholder value."
  [[ "$api_url" != *"YOUR-SERVER"* ]] || die "API_URL still has placeholder value."
  [[ "$redis_url" != *"YOUR-SERVER"* ]] || die "REDIS_URL still has placeholder value."
}

detect_default_interface() {
  ip route show default 2>/dev/null | awk 'NR==1 {print $5}'
}

is_truthy() {
  case "${1,,}" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

load_image() {
  local image_name="$1"
  local image_tar="$2"
  local required="${3:-true}"

  if [[ -f "$image_tar" ]]; then
    log "Loading image tar: $image_tar"
    docker load -i "$image_tar" >/dev/null
  fi

  if docker image inspect "$image_name" >/dev/null 2>&1; then
    return 0
  fi

  if [[ "$required" == "true" ]]; then
    die "Image $image_name not found. Include image tar in the bundle."
  fi

  log "WARNING: Optional image $image_name is missing."
  return 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-url)
      API_URL_OVERRIDE="${2:-}"
      shift 2
      ;;
    --redis-url)
      REDIS_URL_OVERRIDE="${2:-}"
      shift 2
      ;;
    --redis-password)
      REDIS_PASSWORD_OVERRIDE="${2:-}"
      shift 2
      ;;
    --network-interface)
      NETWORK_INTERFACE_OVERRIDE="${2:-}"
      shift 2
      ;;
    --promiscuous-mode)
      PROMISCUOUS_MODE_OVERRIDE="${2:-}"
      shift 2
      ;;
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
    --image-tar)
      IMAGE_TAR="${2:-}"
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
    --firewall-image-tar)
      FIREWALL_IMAGE_TAR="${2:-}"
      shift 2
      ;;
    --firewall-sync-enabled)
      FIREWALL_SYNC_ENABLED_OVERRIDE="${2:-}"
      shift 2
      ;;
    --skip-docker-install)
      SKIP_DOCKER_INSTALL="true"
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
ensure_docker

mkdir -p "$INSTALL_DIR"

if [[ ! -f "$ENV_SOURCE" ]]; then
  if [[ -f "$ENV_TEMPLATE" ]]; then
    cp "$ENV_TEMPLATE" "$ENV_SOURCE"
  else
    die "Missing agent.env and agent.env.example."
  fi
fi

[[ -n "$API_URL_OVERRIDE" ]] && update_env_key "$ENV_SOURCE" "API_URL" "$API_URL_OVERRIDE"
[[ -n "$REDIS_URL_OVERRIDE" ]] && update_env_key "$ENV_SOURCE" "REDIS_URL" "$REDIS_URL_OVERRIDE"
[[ -n "$REDIS_PASSWORD_OVERRIDE" ]] && update_env_key "$ENV_SOURCE" "REDIS_PASSWORD" "$REDIS_PASSWORD_OVERRIDE"
[[ -n "$NETWORK_INTERFACE_OVERRIDE" ]] && update_env_key "$ENV_SOURCE" "NETWORK_INTERFACE" "$NETWORK_INTERFACE_OVERRIDE"
[[ -n "$PROMISCUOUS_MODE_OVERRIDE" ]] && update_env_key "$ENV_SOURCE" "PROMISCUOUS_MODE" "$PROMISCUOUS_MODE_OVERRIDE"
[[ -n "$FIREWALL_SYNC_ENABLED_OVERRIDE" ]] && update_env_key "$ENV_SOURCE" "FIREWALL_SYNC_ENABLED" "$FIREWALL_SYNC_ENABLED_OVERRIDE"

if [[ -z "$(read_env_key "$ENV_SOURCE" "FIREWALL_SYNC_ENABLED")" ]]; then
  update_env_key "$ENV_SOURCE" "FIREWALL_SYNC_ENABLED" "true"
fi

current_iface="$(read_env_key "$ENV_SOURCE" "NETWORK_INTERFACE")"
if [[ -z "$current_iface" ]]; then
  auto_iface="$(detect_default_interface || true)"
  if [[ -n "$auto_iface" ]]; then
    update_env_key "$ENV_SOURCE" "NETWORK_INTERFACE" "$auto_iface"
    log "Auto-selected interface: $auto_iface"
  else
    log "Could not auto-detect interface; core will fallback internally."
  fi
fi

api_url="$(read_env_key "$ENV_SOURCE" "API_URL")"
redis_url="$(read_env_key "$ENV_SOURCE" "REDIS_URL")"
validate_url_placeholders "$api_url" "$redis_url"

cp "$ENV_SOURCE" "$INSTALL_DIR/agent.env"
cp "$SCRIPT_DIR/start-agent.sh" "$INSTALL_DIR/start-agent.sh"
cp "$SCRIPT_DIR/uninstall.sh" "$INSTALL_DIR/uninstall.sh"
chmod 750 "$INSTALL_DIR/start-agent.sh" "$INSTALL_DIR/uninstall.sh"

if [[ -f "$SCRIPT_DIR/firewall-sync.py" ]]; then
  cp "$SCRIPT_DIR/firewall-sync.py" "$INSTALL_DIR/firewall-sync.py"
  chmod 640 "$INSTALL_DIR/firewall-sync.py"
fi

load_image "$IMAGE_NAME" "$IMAGE_TAR" "true"

if docker ps -a --format '{{.Names}}' | grep -Fxq "$CONTAINER_NAME"; then
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
fi

docker run -d \
  --name "$CONTAINER_NAME" \
  --network host \
  --restart unless-stopped \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --env-file "$INSTALL_DIR/agent.env" \
  "$IMAGE_NAME" >/dev/null

firewall_sync_enabled="$(read_env_key "$INSTALL_DIR/agent.env" "FIREWALL_SYNC_ENABLED")"
if is_truthy "${firewall_sync_enabled:-true}"; then
  if docker ps -a --format '{{.Names}}' | grep -Fxq "$FIREWALL_CONTAINER_NAME"; then
    docker rm -f "$FIREWALL_CONTAINER_NAME" >/dev/null 2>&1 || true
  fi

  if load_image "$FIREWALL_IMAGE_NAME" "$FIREWALL_IMAGE_TAR" "false"; then
    docker run -d \
      --name "$FIREWALL_CONTAINER_NAME" \
      --network host \
      --restart unless-stopped \
      --cap-add NET_ADMIN \
      --cap-add NET_RAW \
      --env-file "$INSTALL_DIR/agent.env" \
      "$FIREWALL_IMAGE_NAME" >/dev/null
    log "Firewall sync container started: $FIREWALL_CONTAINER_NAME"
  else
    log "WARNING: Firewall sync is enabled but firewall image is unavailable. Core agent still started."
  fi
else
  if docker ps -a --format '{{.Names}}' | grep -Fxq "$FIREWALL_CONTAINER_NAME"; then
    docker rm -f "$FIREWALL_CONTAINER_NAME" >/dev/null 2>&1 || true
  fi
  log "Firewall sync disabled by FIREWALL_SYNC_ENABLED=${firewall_sync_enabled:-false}"
fi

log "Revenix Linux agent installed."
log "Container: $CONTAINER_NAME"
log "Install dir: $INSTALL_DIR"
log "Image: $IMAGE_NAME"
log ""
log "Verify:"
log "  docker ps --filter name=$CONTAINER_NAME"
log "  docker logs -f $CONTAINER_NAME"
if is_truthy "${firewall_sync_enabled:-true}"; then
  log "  docker logs -f $FIREWALL_CONTAINER_NAME"
fi
