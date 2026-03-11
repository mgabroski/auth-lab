#!/usr/bin/env bash
# scripts/stop.sh
#
# WHY:
# - Single command to stop local Docker-backed topology pieces consistently.
# - Supports BOTH intentional local modes:
#   - infra-only host-run mode
#   - full stack topology mode
#
# HOW TO USE:
#   ./scripts/stop.sh          # stop BOTH stack + infra (safe default)
#   ./scripts/stop.sh --all    # same as default
#   ./scripts/stop.sh --infra  # stop only infra-only host-run containers
#   ./scripts/stop.sh --stack  # stop only full topology stack containers

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INFRA_COMPOSE="$ROOT_DIR/infra/docker-compose-infra.yml"
STACK_COMPOSE="$ROOT_DIR/infra/docker-compose.yml"
MODE="${1:---all}"

stop_compose() {
  local file="$1"
  local label="$2"

  echo "🧹 Stopping ${label}..."
  docker compose -f "$file" down --remove-orphans >/dev/null 2>&1 || true
}

case "$MODE" in
  --all)
    stop_compose "$STACK_COMPOSE" "full stack"
    stop_compose "$INFRA_COMPOSE" "infra-only stack"
    echo "✅ Docker-backed local modes stopped."
    echo "ℹ️  Host-run frontend/backend processes, if started manually, must be stopped in their own terminal."
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
    echo "Usage: ./scripts/stop.sh [--all|--infra|--stack]"
    exit 1
    ;;
 esac