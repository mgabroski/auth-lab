#!/usr/bin/env bash
# scripts/verify.sh
#
# Full local verification gate.
# Called by: yarn verify → git push (pre-push hook)
# Also callable directly: yarn verify
#
# WHAT RUNS:
#   fmt:check   — Prettier format check
#   lint        — ESLint
#   typecheck   — tsc backend + frontend
#   test        — delegates to scripts/test.sh which runs:
#                   backend tests (against auth_lab_test)
#                   frontend unit tests
#                   E2E smoke suite (when stack is running)
#
# WHY test.sh owns the E2E decision:
#   test.sh already checks whether the stack is running and runs E2E
#   conditionally. Running yarn test:e2e again here would execute E2E
#   twice in a single verify run, exhausting rate limit counters on the
#   second pass and causing flaky failures on member login.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "🔍 Checking format..."
yarn fmt:check

echo "🔍 Linting..."
yarn lint

echo "🔍 Typechecking..."
yarn typecheck

echo "🧪 Running tests..."
yarn test

echo ""
echo "✅ All checks passed."