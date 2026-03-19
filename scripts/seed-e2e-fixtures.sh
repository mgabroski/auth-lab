#!/usr/bin/env bash
# scripts/seed-e2e-fixtures.sh
#
# WHY:
# - Convenience wrapper that runs the E2E fixture seed inside the running
#   backend container.
# - Use this locally after `./scripts/stack.sh up` to prepare the admin persona
#   required by real-stack Playwright smoke tests.
# - In CI, the seed-e2e-fixtures step in the frontend.yml e2e job runs the
#   equivalent docker compose exec command directly.
#
# PREREQUISITES:
#   ./scripts/stack.sh up   — full stack must be running and healthy
#   jq                      — not required by this script, but stack.sh test needs it
#
# USAGE:
#   ./scripts/seed-e2e-fixtures.sh
#
# WHAT IT CREATES (idempotent):
#   Tenant:    goodwill-open (created by dev seed during backend startup)
#   User:      e2e-admin@example.com  name: "E2E Admin"  email_verified: true
#   Password:  Password123!
#   Identity:  password provider
#   Membership: ADMIN, ACTIVE in goodwill-open
#   MFA:        none (so login returns MFA_SETUP_REQUIRED)
#
# WHAT THIS ENABLES:
#   auth.spec.ts — "admin login without MFA continues to /auth/mfa/setup"

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_ENV_FILE="$ROOT_DIR/infra/.env.stack"
COMPOSE="docker compose --env-file $COMPOSE_ENV_FILE -f $ROOT_DIR/infra/docker-compose.yml"

echo "🔧  Running E2E fixture seed inside backend container..."
$COMPOSE exec -T backend yarn workspace @auth-lab/backend db:seed:e2e

echo ""
echo "✅  E2E fixtures seeded."
echo ""
echo "   Persona:   e2e-admin@example.com / Password123!"
echo "   Tenant:    goodwill-open (ADMIN, ACTIVE, no MFA)"
echo "   Effect:    login will return MFA_SETUP_REQUIRED"
echo ""
echo "   Run real-stack Playwright tests with:"
echo "     yarn workspace frontend test:e2e:real-stack"