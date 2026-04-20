#!/usr/bin/env bash
# scripts/test.sh
#
# Runs the repo test suite used by local verify flows.
#
# WHY auth_lab_test is created here:
# - In CI, backend tests use a separate auth_lab_test database (see backend-tests.yml).
#   Locally, backend/.env points to auth_lab — the same DB as the running dev server.
#   Running yarn test:backend locally would truncate auth_lab, destroying the dev
#   server's data and causing every subsequent Playwright test to fail with 500s.
# - We create and migrate auth_lab_test locally so backend tests run against an
#   isolated database, exactly as CI does. The running dev server is never touched.
#
# WHY Redis flush before E2E:
# - backend tests may leave sessions and rate limit counters in Redis.
# - Flushing resets all counters. Sessions are re-created by each test's login step.
#
# WHY local Playwright here is auth-only:
# - The default local dev topology (yarn dev) is host-run:
#     frontend -> localhost:3000
#     cp       -> localhost:3002
# - In that mode Caddy is NOT the active public entrypoint for cp.lvh.me:3000,
#   which is the canonical browser-proof host for Control Plane topology work.
# - CP smoke therefore belongs to the full-stack / real-proxy topology:
#     yarn dev:stack
#     yarn workspace frontend test:e2e:cp
#
# SEQUENCE:
#   1. Ensure auth_lab_test exists and is migrated
#   2. Run backend tests against auth_lab_test (dev server untouched)
#   3. Run frontend unit tests
#   4. Run Control Plane unit tests
#   5. If tenant stack is running:
#      a. Seed E2E fixtures (idempotent — does not disturb running dev server)
#      b. Flush Redis
#      c. Run Playwright tenant auth smoke only

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# ── Ensure auth_lab_test DB exists and is migrated ────────────────────────────
# This mirrors exactly what the CI backend-tests.yml job does.

echo "🗄️  Ensuring auth_lab_test database exists..."
docker exec auth-lab-postgres \
  psql -U auth_lab -d postgres \
  -c "CREATE DATABASE auth_lab_test OWNER auth_lab;" \
  2>/dev/null || true
echo "   Done."

echo "🗄️  Running migrations on auth_lab_test..."
DATABASE_URL=postgres://auth_lab:auth_lab@localhost:5432/auth_lab_test \
  yarn workspace @auth-lab/backend db:migrate
echo "   Done."

# ── Backend tests — against auth_lab_test, not auth_lab ──────────────────────

echo ""
echo "🧪 Running backend tests (using auth_lab_test — dev server DB untouched)..."
DATABASE_URL=postgres://auth_lab:auth_lab@localhost:5432/auth_lab_test \
  NODE_ENV=test \
  yarn workspace @auth-lab/backend test

# ── Frontend unit tests ───────────────────────────────────────────────────────

echo ""
echo "🧪 Running frontend unit tests..."
yarn test:frontend:unit

# ── Control Plane unit tests ──────────────────────────────────────────────────

echo ""
echo "🧪 Running Control Plane unit tests..."
yarn test:cp

# ── E2E — only when tenant stack is running ──────────────────────────────────

echo ""
if curl -sf http://goodwill-ca.lvh.me:3000/api/health >/dev/null 2>&1; then
  echo "🧬 Seeding E2E fixtures (idempotent)..."
  yarn seed:e2e

  echo ""
  echo "🧹 Flushing Redis (resets rate limit counters and stale sessions)..."
  docker exec auth-lab-redis redis-cli FLUSHALL > /dev/null
  echo "   Redis flushed."

  echo ""
  echo "🐳 Tenant stack is running — running E2E auth smoke tests..."
  yarn workspace frontend test:e2e:auth
  echo "✅ E2E auth smoke passed."
else
  echo "ℹ️  Tenant stack not running — E2E skipped."
  echo "   Start the stack with yarn dev, then run yarn test again."
  echo "   For CP proxy-host smoke on http://cp.lvh.me:3000, use yarn dev:stack and run:"
  echo "   yarn workspace frontend test:e2e:cp"
fi

echo ""
echo "✅ Tests complete."