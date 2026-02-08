#!/usr/bin/env bash
# scripts/dev.sh
#
# WHY:
# - Single command to start the local development infrastructure (Postgres + Redis).
# - We intentionally keep infra startup in a script so later we can add:
#   - running Kysely migrations
#   - starting the backend in watch mode
#   without changing how developers work.
#
# HOW TO USE:
#   chmod +x scripts/*.sh
#   ./scripts/dev.sh
#
# WHAT IT DOES:
# 1) docker compose up -d (infra only)
# 2) waits until Postgres is ready (so future migrations won't fail)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "🔧 Starting infra (Postgres + Redis)..."
docker compose -f "$ROOT_DIR/infra/docker-compose.yml" up -d

echo "⏳ Waiting for Postgres to be ready..."
until docker exec auth-lab-postgres pg_isready -U auth_lab -d auth_lab >/dev/null 2>&1; do
  sleep 1
done

echo "✅ Infra is up."
echo ""
echo "Next (when backend exists): we'll run migrations and start the API automatically from here."
