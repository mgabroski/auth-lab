#!/usr/bin/env bash
# scripts/reset-db.sh
#
# WHY:
# - Reset local Postgres + Redis volumes without guessing which compose file
#   currently owns them.
# - Supports BOTH intentional local modes:
#   - infra-only host-run mode
#   - full stack topology mode
#
# HOW TO USE:
#   ./scripts/reset-db.sh          # wipe BOTH stack + infra volumes (safe default)
#   ./scripts/reset-db.sh --all    # same as default
#   ./scripts/reset-db.sh --infra  # wipe only host-run infra volumes
#   ./scripts/reset-db.sh --stack  # wipe only full-stack volumes
#
# WARNING:
# - This deletes LOCAL development data.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INFRA_COMPOSE="$ROOT_DIR/infra/docker-compose-infra.yml"
STACK_COMPOSE="$ROOT_DIR/infra/docker-compose.yml"
MODE="${1:---all}"

reset_compose() {
  local file="$1"
  local label="$2"

  echo "⚠️  Resetting ${label} volumes..."
  docker compose -f "$file" down -v --remove-orphans >/dev/null 2>&1 || true
}

case "$MODE" in
  --all)
    reset_compose "$STACK_COMPOSE" "full stack"
    reset_compose "$INFRA_COMPOSE" "infra-only stack"
    echo "✅ All local Docker volumes reset."
    ;;

  --infra)
    reset_compose "$INFRA_COMPOSE" "infra-only stack"
    echo "✅ Infra-only volumes reset."
    ;;

  --stack)
    reset_compose "$STACK_COMPOSE" "full stack"
    echo "✅ Full-stack volumes reset."
    ;;

  *)
    echo "Usage: ./scripts/reset-db.sh [--all|--infra|--stack]"
    exit 1
    ;;
 esac