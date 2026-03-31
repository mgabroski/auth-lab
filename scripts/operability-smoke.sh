#!/usr/bin/env bash
# scripts/operability-smoke.sh
#
# WHY:
# - Stage 3 requires concrete, runnable operability proof.
# - This script validates that the deployed stack exposes real operator signals
#   through the same proxy path the app uses in practice.
# - It is intentionally small and durable: health, correlation header, metrics
#   export, and one deterministic failure metric increment.
#
# CURRENT PROOF:
#   OS-01: /api/health is reachable through the proxy
#   OS-02: x-request-id is returned on a normal proxied request
#   OS-03: /api/metrics is reachable through the proxy
#   OS-04: /api/metrics returns Prometheus text
#   OS-05: a deterministic failed login increments auth_login_failures_total
#
# RULES:
# - Run against the live stack, not mocks.
# - Use localhost + explicit Host header to avoid CI hostname->Docker routing issues.
# - Assert only low-cardinality, durable signals.
# - Do not depend on dashboards, Grafana, or external infra.
#
# USAGE:
#   ./scripts/operability-smoke.sh
#   ./scripts/operability-smoke.sh --verbose
#
# EXIT:
#   0 = all checks passed
#   1 = one or more checks failed

set -euo pipefail

PROXY_HOST="${PROXY_HOST:-localhost}"
PROXY_PORT="${PROXY_PORT:-3000}"
BASE_URL="http://${PROXY_HOST}:${PROXY_PORT}"

TENANT_HOST="${TENANT_HOST:-goodwill-ca.lvh.me}"
LOGIN_EMAIL="${LOGIN_EMAIL:-system_admin@example.com}"
LOGIN_BAD_PASSWORD="${LOGIN_BAD_PASSWORD:-DefinitelyWrongPassword123!}"

VERBOSE="${1:-}"
PASS=0
FAIL=0
FAILED_CHECKS=""

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

log()   { echo "  $*"; }
pass()  { echo "  ✅  $*"; PASS=$((PASS + 1)); }
fail()  { echo "  ❌  $*"; FAIL=$((FAIL + 1)); FAILED_CHECKS="${FAILED_CHECKS}\n  - $*"; }

curl_maybe_verbose() {
  if [ "${VERBOSE}" = "--verbose" ]; then
    curl -sv "$@" 2>&1
  else
    curl -s "$@"
  fi
}

wait_for_proxy() {
  echo "⏳ Waiting for proxy at ${BASE_URL}..."
  local attempts=0

  until curl -sf -o /dev/null -H "Host: ${TENANT_HOST}" "${BASE_URL}/api/health" 2>/dev/null; do
    attempts=$((attempts + 1))
    if [ "${attempts}" -ge 30 ]; then
      echo "❌ Proxy did not become reachable after 30 attempts."
      exit 1
    fi
    sleep 2
  done

  echo "✅ Proxy is reachable."
}

extract_metric_value() {
  local file="$1"
  local expected_prefix="$2"

  local line
  line="$(grep -F "${expected_prefix}" "${file}" | head -n 1 || true)"

  if [ -z "${line}" ]; then
    echo ""
    return 0
  fi

  echo "${line}" | awk '{print $NF}'
}

assert_integer() {
  local value="$1"
  [[ "${value}" =~ ^[0-9]+$ ]]
}

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  Hubins Operability Smoke"
echo "  Stack: ${BASE_URL}  Tenant: ${TENANT_HOST}"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

wait_for_proxy

# ── OS-01 / OS-02: /api/health + x-request-id ──────────────────────────────
echo "OS-01 / OS-02: /api/health returns 200 and exposes x-request-id"

HEALTH_HEADERS_FILE="${TMP_DIR}/health-headers.txt"
HEALTH_BODY_FILE="${TMP_DIR}/health-body.txt"

HEALTH_CODE="$(curl -sS \
  -D "${HEALTH_HEADERS_FILE}" \
  -o "${HEALTH_BODY_FILE}" \
  -w "%{http_code}" \
  -H "Host: ${TENANT_HOST}" \
  -H "X-Request-Id: operability-smoke-health-001" \
  "${BASE_URL}/api/health")"

if [ "${HEALTH_CODE}" = "200" ]; then
  REQUEST_ID_HEADER="$(grep -i '^x-request-id:' "${HEALTH_HEADERS_FILE}" | head -n 1 | cut -d':' -f2- | tr -d '\r' | xargs || true)"

  if [ -n "${REQUEST_ID_HEADER}" ]; then
    pass "/api/health returned 200 and x-request-id=${REQUEST_ID_HEADER}"
  else
    fail "/api/health returned 200 but x-request-id header was missing"
  fi
else
  fail "/api/health expected 200, got ${HEALTH_CODE}"
fi

# ── OS-03 / OS-04: /api/metrics through proxy ───────────────────────────────
echo ""
echo "OS-03 / OS-04: /api/metrics is reachable and returns Prometheus text"

METRICS_HEADERS_BEFORE="${TMP_DIR}/metrics-before-headers.txt"
METRICS_BODY_BEFORE="${TMP_DIR}/metrics-before.txt"

METRICS_CODE_BEFORE="$(curl -sS \
  -D "${METRICS_HEADERS_BEFORE}" \
  -o "${METRICS_BODY_BEFORE}" \
  -w "%{http_code}" \
  -H "Host: ${TENANT_HOST}" \
  "${BASE_URL}/api/metrics")"

if [ "${METRICS_CODE_BEFORE}" = "200" ]; then
  CONTENT_TYPE="$(grep -i '^content-type:' "${METRICS_HEADERS_BEFORE}" | head -n 1 | cut -d':' -f2- | tr -d '\r' | xargs || true)"

  if echo "${CONTENT_TYPE}" | grep -qi 'text/plain'; then
    if grep -q '^# HELP http_requests_total ' "${METRICS_BODY_BEFORE}" && \
       grep -q '^# TYPE http_requests_total counter' "${METRICS_BODY_BEFORE}" && \
       grep -q '^# HELP auth_login_failures_total ' "${METRICS_BODY_BEFORE}"; then
      pass "/api/metrics returned Prometheus text with expected metric families"
    else
      fail "/api/metrics returned 200 but expected metric families were missing"
    fi
  else
    fail "/api/metrics returned 200 but content-type was not Prometheus text (${CONTENT_TYPE})"
  fi
else
  fail "/api/metrics expected 200, got ${METRICS_CODE_BEFORE}"
fi

# ── OS-05: failed login increments auth_login_failures_total ────────────────
echo ""
echo "OS-05: failed login increments auth_login_failures_total"

LOGIN_FAILURE_METRIC_PREFIX='auth_login_failures_total{reason="unauthorized",code="UNAUTHORIZED",status="401"}'
BEFORE_VALUE="$(extract_metric_value "${METRICS_BODY_BEFORE}" "${LOGIN_FAILURE_METRIC_PREFIX}")"

if [ -z "${BEFORE_VALUE}" ]; then
  BEFORE_VALUE="0"
fi

if ! assert_integer "${BEFORE_VALUE}"; then
  fail "Initial auth_login_failures_total value was not an integer (${BEFORE_VALUE})"
else
  LOGIN_CODE="$(curl -sS \
    -o "${TMP_DIR}/login-response.txt" \
    -w "%{http_code}" \
    -X POST \
    -H "Host: ${TENANT_HOST}" \
    -H "Content-Type: application/json" \
    -H "X-Request-Id: operability-smoke-login-failure-001" \
    -d "{\"email\":\"${LOGIN_EMAIL}\",\"password\":\"${LOGIN_BAD_PASSWORD}\"}" \
    "${BASE_URL}/api/auth/login")"

  if [ "${LOGIN_CODE}" != "401" ]; then
    fail "Deterministic failed login expected 401, got ${LOGIN_CODE}"
  else
    METRICS_HEADERS_AFTER="${TMP_DIR}/metrics-after-headers.txt"
    METRICS_BODY_AFTER="${TMP_DIR}/metrics-after.txt"

    METRICS_CODE_AFTER="$(curl -sS \
      -D "${METRICS_HEADERS_AFTER}" \
      -o "${METRICS_BODY_AFTER}" \
      -w "%{http_code}" \
      -H "Host: ${TENANT_HOST}" \
      "${BASE_URL}/api/metrics")"

    if [ "${METRICS_CODE_AFTER}" != "200" ]; then
      fail "Second /api/metrics read expected 200, got ${METRICS_CODE_AFTER}"
    else
      AFTER_VALUE="$(extract_metric_value "${METRICS_BODY_AFTER}" "${LOGIN_FAILURE_METRIC_PREFIX}")"

      if [ -z "${AFTER_VALUE}" ]; then
        fail "auth_login_failures_total metric line missing after failed login"
      elif ! assert_integer "${AFTER_VALUE}"; then
        fail "auth_login_failures_total after-value was not an integer (${AFTER_VALUE})"
      else
        EXPECTED_AFTER=$((BEFORE_VALUE + 1))

        if [ "${AFTER_VALUE}" = "${EXPECTED_AFTER}" ]; then
          pass "Failed login incremented auth_login_failures_total from ${BEFORE_VALUE} to ${AFTER_VALUE}"
        else
          fail "Expected auth_login_failures_total to move from ${BEFORE_VALUE} to ${EXPECTED_AFTER}, got ${AFTER_VALUE}"
        fi
      fi
    fi
  fi
fi

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "═══════════════════════════════════════════════════════════════════"

if [ "${FAIL}" -gt 0 ]; then
  echo ""
  echo "Failed checks:${FAILED_CHECKS}"
  echo ""
  echo "❌ Operability smoke FAILED — Stage 3 signals are not yet trustworthy."
  exit 1
else
  echo ""
  echo "✅ Operability smoke passed."
  echo "   Request correlation, metrics export, and one real failure counter are working through the proxy path."
  exit 0
fi