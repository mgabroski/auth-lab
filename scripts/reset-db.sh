#!/usr/bin/env bash
# scripts/reset-db.sh
#
# WHY:
# - Sometimes you need a clean slate (drop all local Postgres + Redis data).
# - This removes Docker volumes, which deletes the stored data.
#
# HOW TO USE:
#   ./scripts/reset-db.sh
#
# WARNING:
# - This deletes your LOCAL dev database data.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "⚠️  Resetting infra volumes (this DELETES local Postgres/Redis data)..."
docker compose -f "$ROOT_DIR/infra/docker-compose.yml" down -v
echo "✅ Reset complete."
