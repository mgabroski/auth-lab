/**
 * frontend/test/e2e/helpers/local-oidc.ts
 *
 * WHY:
 * - The local OIDC server (infra/oidc-server/) exposes POST /code as a CI
 *   test helper. It accepts an identity payload (email, sub, nonce) and
 *   returns a short-lived authorization_code that the test can hand to the
 *   backend SSO callback endpoint.
 * - This closes the gap where FakeSsoAdapter (backend unit/E2E tests) bypasses
 *   real JWKS fetch and JWT signature verification. Using the local OIDC server
 *   forces the full jose jwtVerify() path: JWKS HTTP fetch → RSA-256 signature
 *   check → iss/aud/exp enforcement → nonce enforcement.
 *
 * RULES:
 * - Only call these helpers when the local OIDC server is active (CI with the
 *   docker-compose-ci-oidc.yml overlay, or local dev with that same overlay).
 * - The OIDC server URL is always localhost:9998 from the Playwright runner
 *   (the Docker port is exposed). The backend container reaches it via the
 *   Docker network name (local-oidc:9998) — that is not the Playwright URL.
 * - Never import from backend source — this helper is frontend/test only.
 */

const LOCAL_OIDC_BASE_URL = 'http://localhost:9998';

/**
 * Registers a desired SSO identity with the local OIDC server and returns a
 * short-lived authorization_code.
 *
 * The `nonce` must match the nonce that the backend embedded in the sso-state
 * cookie during SSO start. Extract it from the SSO start redirect URL query
 * params before calling this function.
 *
 * The returned code is single-use and expires in 2 minutes.
 */
export async function registerOidcIdentity(opts: {
  email: string;
  sub: string;
  nonce: string;
  name?: string;
  /** Default: true. Set false to test email_not_verified rejection on Google path. */
  emailVerified?: boolean;
}): Promise<{ code: string }> {
  const res = await fetch(`${LOCAL_OIDC_BASE_URL}/code`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      email: opts.email,
      sub: opts.sub,
      nonce: opts.nonce,
      name: opts.name ?? 'SSO Test User',
      email_verified: opts.emailVerified ?? true,
    }),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '(unreadable)');
    throw new Error(
      `Local OIDC POST /code failed: ${res.status}\n` +
        `Body: ${body}\n` +
        `Is the stack running with the OIDC overlay? ` +
        `docker compose -f infra/docker-compose.yml -f infra/docker-compose-ci-oidc.yml up`,
    );
  }

  const json = (await res.json()) as { code: string };

  if (!json.code || typeof json.code !== 'string') {
    throw new Error(`Local OIDC POST /code returned unexpected shape: ${JSON.stringify(json)}`);
  }

  return { code: json.code };
}

/**
 * Returns true when the local OIDC server appears to be running and healthy.
 * Use this to guard tests that require the OIDC overlay stack.
 */
export async function isLocalOidcReachable(): Promise<boolean> {
  try {
    const res = await fetch(`${LOCAL_OIDC_BASE_URL}/.well-known/jwks.json`, {
      signal: AbortSignal.timeout(2000),
    });
    return res.ok;
  } catch {
    return false;
  }
}
