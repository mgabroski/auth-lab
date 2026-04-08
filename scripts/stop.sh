#!/usr/bin/env bash
# scripts/stop.sh
#
# WHY:
# - Single command to stop local Docker-backed topology pieces consistently.
# - Also stops host-run backend/frontend/cp processes tracked by repo-local PID files.
#
# HOW TO USE:
#   ./scripts/stop.sh          # stop host-run services + Docker-backed local modes
#   ./scripts/stop.sh --all    # same as default
#   ./scripts/stop.sh --host   # stop only host-run backend/frontend/cp
#   ./scripts/stop.sh --infra  # stop only infra-only host-run containers
#   ./scripts/stop.sh --stack  # stop only full topology stack containers

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INFRA_COMPOSE="$ROOT_DIR/infra/docker-compose-infra.yml"
STACK_COMPOSE="$ROOT_DIR/infra/docker-compose.yml"
MODE="${1:---all}"

# shellcheck source=./lib/host-services.sh
source "$ROOT_DIR/scripts/lib/host-services.sh"

stop_compose() {
  local file="$1"
  local label="$2"

  echo "🧹 Stopping ${label}..."
  docker compose -f "$file" down --remove-orphans >/dev/null 2>&1 || true
}

case "$MODE" in
  --all)
    stop_default_host_services
    stop_compose "$STACK_COMPOSE" "full stack"
    stop_compose "$INFRA_COMPOSE" "infra-only stack"
    echo "✅ Host-run services and Docker-backed local modes stopped."
    ;;

  --host)
    stop_default_host_services
    echo "✅ Host-run services stopped."
    ;;

  --infra)
    stop_compose "$INFRA_COMPOSE" "infra-only stack"
    echo "✅ Infra-only stack stopped."
    ;;

  --stack)
    stop_compose "$STACK_COMPOSE" "full stack"
    echo "✅ Full stack stopped."
    ;;

  *)
    echo "Usage: ./scripts/stop.sh [--all|--host|--infra|--stack]"
    exit 1
    ;;
esac