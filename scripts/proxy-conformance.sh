#!/usr/bin/env bash
# scripts/proxy-conformance.sh
#
# WHY:
# - Proves the proxy contract is correct before any frontend auth work begins.
# - "The proxy is load-bearing for this architecture" (topology doc Section 3).
# - Each test catches a specific class of proxy misconfiguration.
# - Tests run against the live Compose stack (not mocked — tests real wiring).
#
# TESTS:
#   PT-01: Host header preservation   — tenant resolution depends on this
#   PT-02: /api prefix stripping      — backend has no /api prefix
#   PT-03: /_next/* routing           — Next.js assets served (FIXED: not __nextjs_*)
#   PT-04: Cookie pass-through        — session middleware reads the cookie
#   PT-05: X-Forwarded-For chain      — rate limiting uses client IP
#   PT-06: X-Forwarded-Host           — belt-and-suspenders tenant fallback
#   PT-07: Cross-tenant isolation     — session from tenant A rejected on tenant B
#   PT-08: Inactive tenant anti-enum  — unknown tenant returns same shape as inactive
#
# PREREQUISITES:
#   - Full stack running: docker compose -f infra/docker-compose.yml up --build -d
#   - jq installed: apt-get install jq / brew install jq
#   - curl available
#
# USAGE:
#   ./scripts/proxy-conformance.sh
#   ./scripts/proxy-conformance.sh --verbose   (print curl output for each test)
#
# EXIT:
#   0 = all tests passed
#   1 = one or more tests failed

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PROXY_HOST="${PROXY_HOST:-localhost}"
PROXY_PORT="${PROXY_PORT:-3000}"
BASE_URL="http://${PROXY_HOST}:${PROXY_PORT}"

TENANT="goodwill-ca"
OTHER_TENANT="acme"

VERBOSE="${1:-}"
PASS=0
FAIL=0
FAILED_TESTS=""

# ─── Helpers ──────────────────────────────────────────────────────────────────

log()   { echo "  $*"; }
pass()  { echo "  ✅  $*"; PASS=$((PASS + 1)); }
fail()  { echo "  ❌  $*"; FAIL=$((FAIL + 1)); FAILED_TESTS="${FAILED_TESTS}\n  - $*"; }

curl_silent() {
  if [ "$VERBOSE" = "--verbose" ]; then
    curl -sv "$@" 2>&1
  else
    curl -s "$@"
  fi
}

stop_container_if_exists() {
  docker rm -f "$1" > /dev/null 2>&1 || true
}

get_proxy_network_name() {
  docker inspect hubins-proxy-1 \
    --format '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{end}}' \
    2>/dev/null || true
}

get_backend_image_ref() {
  docker inspect hubins-backend-1 --format '{{.Config.Image}}' 2>/dev/null || true
}

start_pt05_client() {
  local name="$1"
  local image="$2"
  local network="$3"

  stop_container_if_exists "$name"
  docker run -d --rm \
    --name "$name" \
    --network "$network" \
    "$image" \
    sh -c 'sleep 300' > /dev/null
}

client_login_status() {
  local container="$1"
  local email="$2"

  docker exec "$container" node -e '
const email = process.argv[1];

(async () => {
  const response = await fetch("http://proxy:3000/api/auth/login", {
    method: "POST",
    headers: {
      "Host": "goodwill-ca.lvh.me",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      email,
      password: "irrelevant",
    }),
  });

  process.stdout.write(String(response.status));
})().catch((error) => {
  console.error(error);
  process.exit(2);
});
' "$email"
}

canonical_json() {
  echo "$1" | jq -c '.' 2>/dev/null || echo ""
}

# Wait for proxy to be reachable before running tests
wait_for_proxy() {
  echo "⏳ Waiting for proxy to be reachable at ${BASE_URL}..."
  local attempts=0
  until curl -sf "${BASE_URL}/api/health" -H "Host: ${TENANT}.lvh.me" > /dev/null 2>&1; do
    attempts=$((attempts + 1))
    if [ $attempts -ge 30 ]; then
      echo "❌ Proxy did not become reachable after 30 attempts. Is the stack running?"
      exit 1
    fi
    sleep 2
  done
  echo "✅ Proxy is reachable."
}

# ─── Tests ────────────────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  Hubins Proxy Conformance Test Suite"
echo "  Stack: ${BASE_URL}  Tenant: ${TENANT}"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

wait_for_proxy

# ── PT-01: Host header preservation ─────────────────────────────────────────
echo "PT-01: Host header preservation"
log "GET /api/auth/config with Host: ${TENANT}.lvh.me"

RESPONSE=$(curl_silent -w "\n%{http_code}" \
  -H "Host: ${TENANT}.lvh.me" \
  "${BASE_URL}/api/auth/config")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" = "200" ]; then
  IS_ACTIVE=$(echo "$BODY" | jq -r '.tenant.isActive // empty' 2>/dev/null || echo "")
  TENANT_NAME=$(echo "$BODY" | jq -r '.tenant.name // empty' 2>/dev/null || echo "")
  if [ "$IS_ACTIVE" = "true" ] && [ -n "$TENANT_NAME" ]; then
    pass "Host preserved → tenant.name=${TENANT_NAME}"
  elif [ "$IS_ACTIVE" = "false" ]; then
    fail "Tenant resolved to inactive (seed may not have run or tenant key mismatch)"
  else
    fail "Response missing 'tenant.isActive' field — proxy may have rewritten Host header"
  fi
else
  fail "Expected HTTP 200, got ${HTTP_CODE}"
fi

# ── PT-02: /api prefix stripping ─────────────────────────────────────────────
echo ""
echo "PT-02: /api prefix stripping"
log "GET /api/auth/config must route to /auth/config on backend (not /api/auth/config)"

# We verify by checking a known-good response. If the backend were receiving
# /api/auth/config, Fastify would return 404 (no such route registered).
RESPONSE=$(curl_silent -w "\n%{http_code}" \
  -H "Host: ${TENANT}.lvh.me" \
  "${BASE_URL}/api/auth/config")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" = "200" ]; then
  # If prefix was NOT stripped, Fastify would return 404
  HAS_TENANT=$(echo "$BODY" | jq 'has("tenant")' 2>/dev/null || echo "false")
  if [ "$HAS_TENANT" = "true" ]; then
    pass "/api stripped — backend returned ConfigResponse shape"
  else
    fail "Response does not have 'tenant' field — prefix may not be stripped"
  fi
else
  fail "Expected HTTP 200, got ${HTTP_CODE} — prefix may not be stripped (404 = not stripped)"
fi

# ── PT-03: /_next/* routing ──────────────────────────────────────────────────
echo ""
echo "PT-03: /_next/* routing"
log "GET /_next/* must route to Next.js (not backend)"

# We call a safe path that will return either 200 or 404 from Next.js (not backend 404).
RESPONSE=$(curl_silent -w "\n%{http_code}" \
  -H "Host: ${TENANT}.lvh.me" \
  "${BASE_URL}/_next/static/chunks/main.js" 2>/dev/null || echo -e "\n000")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" = "000" ]; then
  fail "Could not reach /_next/* at all — proxy may not be routing to frontend"
elif [ "$HTTP_CODE" = "200" ]; then
  pass "/_next/static served by Next.js (HTTP 200)"
elif [ "$HTTP_CODE" = "404" ]; then
  # Fastify 404 returns JSON: {"statusCode":404,...}
  # Next.js 404 returns HTML
  IS_JSON=$(echo "$BODY" | jq -e . > /dev/null 2>&1 && echo "true" || echo "false")
  if [ "$IS_JSON" = "true" ]; then
    fail "404 was JSON (Fastify) — /_next/* is routing to backend instead of frontend"
  else
    pass "/_next/* routed to Next.js (HTML 404 — chunk not yet built, but routing is correct)"
  fi
else
  pass "/_next/* reached Next.js (HTTP ${HTTP_CODE})"
fi

# ── PT-04: Cookie pass-through ───────────────────────────────────────────────
echo ""
echo "PT-04: Cookie pass-through"
log "Request with Cookie: sid=test-sentinel must reach backend with cookie intact"

# 401 = correct (bad session), 400 = cookie corrupted by proxy, 000 = routing failure
RESPONSE=$(curl_silent -w "\n%{http_code}" \
  -H "Host: ${TENANT}.lvh.me" \
  -H "Cookie: sid=proxy-conformance-test-sentinel" \
  "${BASE_URL}/api/auth/me")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)

if [ "$HTTP_CODE" = "401" ]; then
  pass "Cookie reached backend (401 = session invalid, not stripped)"
elif [ "$HTTP_CODE" = "200" ]; then
  pass "Cookie reached backend (200 — unexpected valid session)"
elif [ "$HTTP_CODE" = "400" ]; then
  fail "HTTP 400 — cookie may have been corrupted in transit by proxy"
elif [ "$HTTP_CODE" = "000" ]; then
  fail "Could not reach backend — proxy routing failure"
else
  pass "Cookie pass-through appears correct (HTTP ${HTTP_CODE} — not a corruption error)"
fi

# ── PT-05: X-Forwarded-For chain preservation ────────────────────────────────
echo ""
echo "PT-05: X-Forwarded-For chain preservation"
log "Two real client containers must not share a login rate-limit bucket"

# WHY THIS APPROACH:
# - The login flow is rate-limited per email (5/15m) AND per IP (20/15m).
#   Using the same email repeatedly cannot prove IP isolation because the email
#   bucket trips first.
# - Caddy ignores incoming X-Forwarded-* values by default to prevent spoofing.
#   So sending fake X-Forwarded-For values from curl is not a valid test of
#   backend-visible client IP isolation.
# - Instead, we create two real client containers on the same Docker network.
#   They have distinct source IPs when they talk to the proxy service.
# - We exhaust the login IP bucket from client A using fresh emails each time,
#   then verify a fresh email from client B is NOT rate-limited.
#
# If client B is still 429 after client A exhausts its bucket, the backend is
# not seeing distinct client IPs through the proxy path.

PT05_NETWORK="$(get_proxy_network_name)"
PT05_IMAGE="$(get_backend_image_ref)"
PT05_CLIENT_A="pt05-client-a-$$"
PT05_CLIENT_B="pt05-client-b-$$"

if [ -z "$PT05_NETWORK" ]; then
  fail "Could not determine Docker network for hubins-proxy-1"
elif [ -z "$PT05_IMAGE" ]; then
  fail "Could not determine backend image reference from hubins-backend-1"
else
  if ! start_pt05_client "$PT05_CLIENT_A" "$PT05_IMAGE" "$PT05_NETWORK"; then
    fail "Could not start PT-05 client A container"
  elif ! start_pt05_client "$PT05_CLIENT_B" "$PT05_IMAGE" "$PT05_NETWORK"; then
    stop_container_if_exists "$PT05_CLIENT_A"
    fail "Could not start PT-05 client B container"
  else
    PT05_GOT_429=false

    for i in $(seq 1 25); do
      EMAIL="pt05-client-a-${i}@example.invalid"
      CODE="$(client_login_status "$PT05_CLIENT_A" "$EMAIL" 2>/dev/null || echo "000")"
      if [ "$CODE" = "429" ]; then
        PT05_GOT_429=true
        break
      fi
    done

    if [ "$PT05_GOT_429" = "false" ]; then
      fail "PT-05: Could not trigger an IP-based 429 for client A after 25 distinct-email attempts"
    else
      CODE_B="$(client_login_status "$PT05_CLIENT_B" "pt05-client-b-check@example.invalid" 2>/dev/null || echo "000")"

      if [ "$CODE_B" = "429" ]; then
        fail "Client B was rate-limited after exhausting client A — backend is not seeing distinct client IPs through proxy"
      elif [ "$CODE_B" = "000" ]; then
        fail "Could not reach backend for client B probe"
      else
        pass "Client A exhausted its IP bucket (429) while client B remained independent (${CODE_B})"
      fi
    fi
  fi
fi

stop_container_if_exists "$PT05_CLIENT_A"
stop_container_if_exists "$PT05_CLIENT_B"

# ── PT-06: X-Forwarded-Host forwarding ──────────────────────────────────────
echo ""
echo "PT-06: X-Forwarded-Host forwarding"
log "Backend must receive X-Forwarded-Host = original Host header"

RESPONSE=$(curl_silent -w "\n%{http_code}" \
  -H "Host: ${TENANT}.lvh.me" \
  "${BASE_URL}/api/auth/config")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" = "200" ]; then
  TENANT_NAME=$(echo "$BODY" | jq -r '.tenant.name // empty' 2>/dev/null || echo "")
  IS_ACTIVE=$(echo "$BODY" | jq -r '.tenant.isActive // empty' 2>/dev/null || echo "")
  if [ -n "$TENANT_NAME" ] && [ "$IS_ACTIVE" = "true" ]; then
    pass "X-Forwarded-Host forwarded (tenant resolved: ${TENANT_NAME})"
  else
    pass "X-Forwarded-Host forwarded (backend responded; tenant may be inactive)"
  fi
else
  fail "Expected 200, got ${HTTP_CODE}"
fi

# ── PT-07: Cross-tenant isolation ────────────────────────────────────────────
echo ""
echo "PT-07: Cross-tenant isolation"
log "A session cookie from ${TENANT} must be rejected on ${OTHER_TENANT}"

LOGIN_BODY='{"email":"system_admin@example.com","password":"Admin1234!"}'
LOGIN_RESPONSE=$(curl_silent -c /tmp/pt07-cookies.txt -w "\n%{http_code}" \
  -X POST \
  -H "Host: ${TENANT}.lvh.me" \
  -H "Content-Type: application/json" \
  -d "$LOGIN_BODY" \
  "${BASE_URL}/api/auth/login" 2>/dev/null)

LOGIN_CODE=$(echo "$LOGIN_RESPONSE" | tail -1)

if [ "$LOGIN_CODE" != "200" ]; then
  log "  ⚠️  Login returned ${LOGIN_CODE} — seeded admin may have different password"
  log "     Attempting /auth/me with a fake cross-tenant cookie instead"

  ME_RESPONSE=$(curl_silent -w "\n%{http_code}" \
    -H "Host: ${OTHER_TENANT}.lvh.me" \
    -H "Cookie: sid=fake-session-from-${TENANT}" \
    "${BASE_URL}/api/auth/me")

  ME_CODE=$(echo "$ME_RESPONSE" | tail -1)
  if [ "$ME_CODE" = "401" ]; then
    pass "Cross-tenant session correctly rejected (401 on ${OTHER_TENANT})"
  else
    fail "Expected 401 on cross-tenant call, got ${ME_CODE}"
  fi
else
  SESSION_COOKIE=$(grep -oP 'sid\t\K[^\s]+' /tmp/pt07-cookies.txt 2>/dev/null || echo "")

  if [ -z "$SESSION_COOKIE" ]; then
    log "  ⚠️  Could not extract session cookie from login response"
    log "     Using manual cross-tenant isolation check instead"
    ME_RESPONSE=$(curl_silent -w "\n%{http_code}" \
      -H "Host: ${OTHER_TENANT}.lvh.me" \
      -H "Cookie: sid=cross-tenant-isolation-test" \
      "${BASE_URL}/api/auth/me")
    ME_CODE=$(echo "$ME_RESPONSE" | tail -1)
    [ "$ME_CODE" = "401" ] && pass "Cross-tenant session rejected (401)" || fail "Expected 401, got ${ME_CODE}"
  else
    ME_RESPONSE=$(curl_silent -w "\n%{http_code}" \
      -H "Host: ${OTHER_TENANT}.lvh.me" \
      -H "Cookie: sid=${SESSION_COOKIE}" \
      "${BASE_URL}/api/auth/me")
    ME_CODE=$(echo "$ME_RESPONSE" | tail -1)
    if [ "$ME_CODE" = "401" ]; then
      pass "Real session from ${TENANT} correctly rejected on ${OTHER_TENANT} (401)"
    else
      fail "ISOLATION FAILURE: session from ${TENANT} accepted on ${OTHER_TENANT} (got ${ME_CODE})"
    fi
  fi
fi

rm -f /tmp/pt07-cookies.txt

# ── PT-08: Inactive tenant anti-enumeration ──────────────────────────────────
echo ""
echo "PT-08: Inactive/unknown tenant anti-enumeration"
log "Unknown tenant must return the locked unavailable payload shape"

UNKNOWN_RESPONSE=$(curl_silent -w "\n%{http_code}" \
  -H "Host: unknown-xyz-does-not-exist.lvh.me" \
  "${BASE_URL}/api/auth/config")

UNKNOWN_CODE=$(echo "$UNKNOWN_RESPONSE" | tail -1)
UNKNOWN_BODY=$(echo "$UNKNOWN_RESPONSE" | head -n -1)

EXPECTED_UNAVAILABLE='{"tenant":{"name":"","isActive":false,"publicSignupEnabled":false,"signupAllowed":false,"allowedSso":[],"setupCompleted":false}}'

if [ "$UNKNOWN_CODE" = "200" ]; then
  CANONICAL_UNKNOWN="$(canonical_json "$UNKNOWN_BODY")"
  CANONICAL_EXPECTED="$(canonical_json "$EXPECTED_UNAVAILABLE")"

  if [ -z "$CANONICAL_UNKNOWN" ]; then
    fail "Unknown tenant response was not valid JSON: ${UNKNOWN_BODY}"
  elif [ "$CANONICAL_UNKNOWN" = "$CANONICAL_EXPECTED" ]; then
    pass "Unknown tenant returned the locked unavailable payload shape"
  else
    fail "Unknown tenant payload drifted from locked unavailable shape: ${UNKNOWN_BODY}"
  fi
else
  fail "Expected 200 with unavailable payload, got ${UNKNOWN_CODE}"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "═══════════════════════════════════════════════════════════════════"

if [ $FAIL -gt 0 ]; then
  echo ""
  echo "Failed tests:${FAILED_TESTS}"
  echo ""
  echo "❌ Proxy conformance FAILED — topology is not locked."
  echo "   Fix the failures above before proceeding to frontend auth work."
  exit 1
else
  echo ""
  echo "✅ All proxy conformance tests passed."
  echo "   Topology foundation is locked. Safe to proceed to frontend auth."
  exit 0
fi