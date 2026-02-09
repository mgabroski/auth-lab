#!/usr/bin/env bash
# scripts/dev.sh
#
# WHY:
# - One command for local dev:
#   1) start infra (postgres + redis)
#   2) run migrations
#   3) generate DB types
#   4) start backend watch
#
# HOW:
# - `yarn dev`

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "🔧 Starting infra (Postgres + Redis)..."
docker compose -f "$ROOT_DIR/infra/docker-compose.yml" up -d

echo "⏳ Waiting for Postgres to be ready..."
until docker exec auth-lab-postgres pg_isready -U auth_lab -d auth_lab >/dev/null 2>&1; do
  sleep 1
done

echo "✅ Infra is up."

echo "📦 Installing dependencies (workspace)..."
cd "$ROOT_DIR"
yarn install

echo "🧩 Ensuring backend env file exists..."
cd "$ROOT_DIR/backend"
if [ ! -f .env ]; then
  cp .env.example .env
  echo "✅ Created backend/.env from backend/.env.example"
fi

echo "🗄️  Running migrations..."
yarn db:migrate

echo "🧬 Generating DB types..."
yarn db:types

echo "🚀 Starting backend (hot reload)..."
yarn dev
