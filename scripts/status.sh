#!/usr/bin/env bash
# scripts/status.sh
#
# WHY:
# - Quick visibility into whether local infra is running and healthy.
# - Avoids "is Postgres up?" or "did Redis start?" guessing.
#
# HOW TO USE:
#   ./scripts/status.sh
#
# WHAT IT DOES:
# - Lists auth-lab containers
# - Shows their running state and health status

set -euo pipefail

echo "📦 auth-lab infrastructure status"
echo "--------------------------------"

docker ps \
  --filter "name=auth-lab-" \
  --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo ""

echo "🔍 Container health checks"
echo "--------------------------"

for container in auth-lab-postgres auth-lab-redis; do
  if docker inspect "$container" >/dev/null 2>&1; then
    health=$(docker inspect --format='{{.State.Health.Status}}' "$container" 2>/dev/null || echo "none")
    echo "$container: $health"
  else
    echo "$container: not running"
  fi
done
