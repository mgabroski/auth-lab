#!/usr/bin/env bash
# scripts/status.sh
#
# WHY:
# - Quick, truthful visibility into BOTH local modes:
#   - Docker-backed stack/infra containers
#   - host-run frontend/backend processes (via HTTP probes)
# - Avoids pretending that host-run processes are Docker-managed.
#
# HOW TO USE:
#   ./scripts/status.sh

set -euo pipefail

probe_url() {
  local label="$1"
  local url="$2"

  if command -v curl >/dev/null 2>&1 && curl -fsS "$url" >/dev/null 2>&1; then
    echo "✅ $label — $url"
  else
    echo "❌ $label — $url"
  fi
}

echo "📦 Hubins local topology status"
echo "--------------------------------"

echo "Docker containers"
echo "-----------------"
docker ps \
  --filter "name=auth-lab-" \
  --filter "name=hubins-" \
  --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo ""
echo "🔍 Container health checks"
echo "--------------------------"

containers="$(
  {
    docker ps -a --filter "name=auth-lab-" --format '{{.Names}}'
    docker ps -a --filter "name=hubins-" --format '{{.Names}}'
  } | sort -u
)"

if [ -z "$containers" ]; then
  echo "No auth-lab / hubins containers found."
else
  printf '%s\n' "$containers" | while IFS= read -r container; do
    state="$(docker inspect --format='{{.State.Status}}' "$container" 2>/dev/null || echo "unknown")"
    health="$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}' "$container" 2>/dev/null || echo "unknown")"
    echo "$container: state=$state health=$health"
  done
fi

echo ""
echo "🌐 HTTP probes"
echo "--------------"
probe_url "Host-run frontend" "http://goodwill-ca.localhost:3000"
probe_url "Host-run backend health" "http://localhost:3001/health"
probe_url "Full-stack public root" "http://goodwill-ca.lvh.me:3000"
probe_url "Full-stack proxy health" "http://goodwill-ca.lvh.me:3000/api/health"

echo ""
echo "🧭 Interpretation"
echo "-----------------"
echo "- Host-run frontend/backend are checked via HTTP only; they are not Docker-managed."
echo "- Full-stack endpoints prove the reverse proxy path is alive."
echo "- Container listings show Docker state for both infra-only and full-stack modes."