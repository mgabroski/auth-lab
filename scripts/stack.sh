#!/usr/bin/env bash
# scripts/stack.sh
#
# WHY:
# - Full Docker topology stack runner.
# - Validates the real deployment wiring: reverse proxy, subdomain tenant
#   resolution, forwarded headers, cookie/session behaviour.
# - NOT the daily inner-loop dev mode. Use yarn dev for that.
#
# WHEN TO USE:
# - Before merging any change to: infra/, proxy config, cookie policy,
#   session middleware, SSO callback URLs, CORS config.
# - When verifying that tenant resolution works through the proxy.
# - On CI for the proxy conformance test gate.
#
# VALIDATES (host-run dev mode does NOT give you these):
# - Real Caddy proxy behaviour (X-Forwarded-For chain, /api prefix stripping)
# - SameSite=Lax cookie behaviour via proxy (OAuth redirect flow)
# - HttpOnly + Path=/ cookie scoping via proxy
# - Single public origin: http://<tenant>.lvh.me:3000
# - Subdomain tenant resolution end-to-end
#
# DOES NOT VALIDATE (local stack is HTTP only):
# - __Host- cookie name prefix (requires HTTPS + Secure flag — production only)
# - True production Secure cookie behaviour
# - Proxy-mediated HMR hot reload (Docker image runs standalone/production build)
#
# USAGE:
#   ./scripts/stack.sh up       — build and start full stack
#   ./scripts/stack.sh down     — stop all containers
#   ./scripts/stack.sh logs     — tail all logs
#   ./scripts/stack.sh rebuild  — rebuild images and restart
#   ./scripts/stack.sh test     — run proxy conformance tests

#!/usr/bin/env bash
# scripts/stack.sh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_ENV_FILE="$ROOT_DIR/infra/.env.stack"
COMPOSE="docker compose --env-file $COMPOSE_ENV_FILE -f $ROOT_DIR/infra/docker-compose.yml"

CMD="${1:-up}"

ensure_env_file() {
  local target_file="$1"
  local example_file="$2"
  local label="$3"

  if [ -f "$target_file" ]; then
    return 0
  fi

  if [ ! -f "$example_file" ]; then
    echo "❌ Missing required example env file: $example_file"
    echo "   Restore the missing file and re-run ./scripts/stack.sh."
    exit 1
  fi

  cp "$example_file" "$target_file"
  echo "✅ Created $target_file from $example_file"
}

ensure_compose_env() {
  ensure_env_file "$COMPOSE_ENV_FILE" "$ROOT_DIR/infra/.env.stack.example" "Infra"
}

case "$CMD" in
  up)
    ensure_compose_env
    echo "🐳 Starting full Hubins stack..."
    $COMPOSE up --build -d
    echo ""
    echo "✅ Stack started."
    echo ""
    echo "  Public app: http://goodwill-ca.lvh.me:3000"
    echo "  Health:     http://goodwill-ca.lvh.me:3000/api/health"
    echo "  Logs:       ./scripts/stack.sh logs"
    echo "  Test:       ./scripts/stack.sh test"
    ;;

  down)
    echo "🛑 Stopping full Hubins stack..."
    $COMPOSE down
    ;;

  logs)
    $COMPOSE logs -f
    ;;

  rebuild)
    ensure_compose_env
    echo "🔨 Rebuilding and restarting full Hubins stack..."
    $COMPOSE down
    $COMPOSE up --build -d
    ;;

  test)
    echo "🧪 Running proxy conformance tests..."
    "$ROOT_DIR/scripts/proxy-conformance.sh"
    ;;

  *)
    echo "Usage: ./scripts/stack.sh [up|down|logs|rebuild|test]"
    exit 1
    ;;
esac