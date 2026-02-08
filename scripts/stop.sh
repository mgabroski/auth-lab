#!/usr/bin/env bash
# scripts/stop.sh
#
# WHY:
# - Single command to stop local infra consistently (no guessing).
#
# HOW TO USE:
#   ./scripts/stop.sh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "🧹 Stopping infra..."
docker compose -f "$ROOT_DIR/infra/docker-compose.yml" down
echo "✅ Done."
