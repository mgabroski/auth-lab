#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-}"
COMPOSE_ENV_FILE="$ROOT_DIR/infra/.env.stack"

ensure_env_file() {
  local target_file="$1"
  local example_file="$2"
  local label="$3"

  if [ -f "$target_file" ]; then
    echo "✅ $label env already present: $target_file"
    return 0
  fi

  if [ ! -f "$example_file" ]; then
    echo "❌ Missing required example env file: $example_file"
    echo "   This repo expects example env templates to be committed."
    echo "   Restore the missing file and re-run yarn dev."
    exit 1
  fi

  cp "$example_file" "$target_file"
  echo "✅ Created $target_file from $example_file"
}

ensure_compose_env() {
  echo "🧩 Ensuring Docker stack env file exists..."
  ensure_env_file "$COMPOSE_ENV_FILE" "$ROOT_DIR/infra/.env.stack.example" "Infra"
}

if [ "$MODE" = "--stack" ]; then
  ensure_compose_env

  echo "🐳 Starting full Docker stack..."
  docker compose \
    --env-file "$COMPOSE_ENV_FILE" \
    -f "$ROOT_DIR/infra/docker-compose.yml" \
    up --build -d
  echo "✅ Full stack started."
  echo "   Public app: http://goodwill-ca.lvh.me:3000"
  echo "   API health: http://goodwill-ca.lvh.me:3000/api/health"
  exit 0
fi

ensure_compose_env

echo "🔧 Starting infra (Postgres + Redis + Mailpit)..."
docker compose \
  --env-file "$COMPOSE_ENV_FILE" \
  -f "$ROOT_DIR/infra/docker-compose-infra.yml" \
  up -d

echo "⏳ Waiting for Postgres to be ready..."
until docker exec auth-lab-postgres pg_isready -U auth_lab -d auth_lab >/dev/null 2>&1; do
  sleep 1
done

echo "✅ Infra is up."

echo "📦 Installing dependencies..."
cd "$ROOT_DIR"
yarn install

echo "🧩 Ensuring backend env file exists..."
ensure_env_file "$ROOT_DIR/backend/.env" "$ROOT_DIR/backend/.env.example" "Backend"

echo "🧩 Ensuring frontend env file exists..."
ensure_env_file "$ROOT_DIR/frontend/.env.local" "$ROOT_DIR/frontend/.env.example" "Frontend"

echo "🗄️  Running migrations..."
yarn workspace @auth-lab/backend db:migrate

echo "🧬 Generating DB types..."
yarn workspace @auth-lab/backend db:types

echo "🚀 Starting backend + frontend (host-run mode)..."
echo "   Public app:   http://goodwill-ca.lvh.me:3000"
echo "   Backend URL:  http://localhost:3001"
echo "   Mailpit UI:   http://localhost:8025"
echo ""
echo "ℹ️  Use goodwill-ca.lvh.me:3000 in the browser for tenant-aware behaviour."
echo "   Plain localhost:3000 does not include a tenant subdomain."
echo "   In host-run mode, browser /api/* is proxied by Next Route Handlers."
echo ""

yarn concurrently \
  "yarn workspace @auth-lab/backend dev" \
  "yarn workspace frontend dev"