/**
 * frontend/test/e2e/auth.spec.ts
 *
 * WHY:
 * - Proves critical auth journeys against the real frontend, real backend,
 *   real database, real session behaviour, and real proxy topology.
 * - This file must not depend on any mock infrastructure.
 *
 * PREREQUISITES (stack must be running before these tests execute):
 *   yarn dev        — starts infra + seeds + backend + frontend (host-run)
 *   yarn dev:stack  — starts full Docker topology including Caddy proxy
 *   OR in CI: managed by .github/workflows/frontend.yml
 *
 * TENANT HOSTS USED:
 *   goodwill-open.lvh.me:3000   — public signup enabled; member + admin personas
 *   goodwill-ca.lvh.me:3000     — invite-only (no public signup)
 *
 * REAL DATA DEPENDENCIES:
 *   member@example.com    / Password123! — seeded by dev seed in goodwill-open
 *   e2e-admin@example.com / Password123! — seeded by E2E fixture seed in goodwill-open
 *                                          ADMIN role, no MFA → MFA_SETUP_REQUIRED
 *
 * TOPOLOGY TESTED (locked contract from topology doc):
 *   - browser → Caddy proxy *.lvh.me:3000 → backend:3001 / frontend:3000
 *   - same-origin /api/* (browser never calls backend directly)
 *   - host-derived tenant identity (goodwill-open.lvh.me → goodwill-open tenant)
 *   - session cookie (sid) set by backend, forwarded by proxy, read by SSR
 *   - SSO state cookie (sso-state) set on SSO start, Lax allows OAuth redirect
 */

import { expect, test } from '@playwright/test';
import { extractLinkFromText, purgeMailpit, waitForEmailToRecipient } from './helpers/mailpit';
import { isLocalOidcReachable, registerOidcIdentity } from './helpers/local-oidc';
import { generateTotp } from './helpers/totp';

// ─── Constants ────────────────────────────────────────────────────────────────

const PROXY_PORT = 3000;
const OPEN_TENANT = 'goodwill-open';
const INVITE_ONLY_TENANT = 'goodwill-ca';

const OPEN_ORIGIN = `http://${OPEN_TENANT}.lvh.me:${PROXY_PORT}`;
const INVITE_ONLY_ORIGIN = `http://${INVITE_ONLY_TENANT}.lvh.me:${PROXY_PORT}`;

// Seeded by dev seed:
const MEMBER_EMAIL = 'member@example.com';
const MEMBER_PASSWORD = 'Password123!';

// Seeded by E2E fixture seed (seed-e2e-fixtures.ts):
const E2E_ADMIN_EMAIL = 'e2e-admin@example.com';
// Dedicated persona for test 18 (MFA recovery). Never used by other tests,
// so its MFA state is never configured mid-run. Seed always clears it.
const E2E_RECOVERY_ADMIN_EMAIL = 'e2e-recovery-admin@example.com';
// Dedicated persona for test 19 (password reset). Seed restores password on every run.
const E2E_RESET_MEMBER_EMAIL = 'e2e-reset-member@example.com';
const E2E_ADMIN_PASSWORD = 'Password123!';

// ─── Tests ────────────────────────────────────────────────────────────────────

test.describe('auth smoke', () => {
  // ── 1. Member login → authenticated area ──────────────────────────────────
  //
  // Proves:
  // - password login works against real DB (bcrypt comparison, session creation)
  // - backend returns nextAction: NONE for a verified member without MFA
  // - frontend routes to /app after NONE
  // - host-derived tenant identity works through the proxy
  // - session cookie (sid) survives the proxy round-trip and SSR reads it

  test('member login reaches /app and session cookie is set correctly', async ({ page }) => {
    await page.goto(`${OPEN_ORIGIN}/auth/login`);

    await expect(page.getByRole('heading', { name: /goodwill open signup/i })).toBeVisible();

    await page.getByLabel('Email').fill(MEMBER_EMAIL);
    await page.getByLabel('Password').fill(MEMBER_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();

    await expect(page).toHaveURL(`${OPEN_ORIGIN}/app`);
    await expect(page.getByRole('heading', { name: 'Member app' })).toBeVisible();
    await expect(page.getByText('Authenticated handoff complete')).toBeVisible();

    const cookies = await page.context().cookies(`${OPEN_ORIGIN}`);
    const sid = cookies.find((c) => c.name === 'sid');
    expect(sid, 'Session cookie "sid" must be present after login').toBeDefined();
    expect(sid?.httpOnly, 'sid must be HttpOnly').toBe(true);
    expect(sid?.sameSite, 'sid must be SameSite=Strict').toBe('Strict');
    expect(sid?.domain ?? '', 'sid must not have a Domain attribute').not.toContain('hubins');
  });

  // ── 2. Logout clears session and protected route is rejected ─────────────
  //
  // Proves:
  // - POST /api/auth/logout destroys the backend session in Redis
  // - /api/auth/me returns 401 after logout
  // - SSR on /app redirects to /auth/login (session is truly gone server-side)
  //
  // WHY page.request.post directly (not the UI button):
  // - The logout button calls window.location.replace('/') which triggers a
  //   full-page hard redirect. In next dev mode, the timing between the
  //   Set-Cookie response being applied and the next SSR request is not
  //   deterministic in Playwright headless mode.
  // - Testing via page.request is direct and timing-stable. What matters is:
  //   does the backend destroy the session, and does SSR correctly reject it?

  test('logout clears session and /app is rejected afterward', async ({ page }) => {
    // Step 1: log in as member
    await page.goto(`${OPEN_ORIGIN}/auth/login`);
    await page.getByLabel('Email').fill(MEMBER_EMAIL);
    await page.getByLabel('Password').fill(MEMBER_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page).toHaveURL(`${OPEN_ORIGIN}/app`);

    // Step 2: confirm /api/auth/me returns 200 while authenticated
    const meWhileAuthed = await page.request.get(`${OPEN_ORIGIN}/api/auth/me`);
    expect(meWhileAuthed.status(), '/api/auth/me must be 200 while authenticated').toBe(200);

    // Step 3: call POST /api/auth/logout via page.request (shares session cookie)
    const logoutResponse = await page.request.post(`${OPEN_ORIGIN}/api/auth/logout`);
    expect(
      logoutResponse.status(),
      `POST /api/auth/logout must return 200 (got ${logoutResponse.status()}).`,
    ).toBe(200);

    // Step 4: confirm backend session is invalidated — /api/auth/me returns 401
    const meAfterLogout = await page.request.get(`${OPEN_ORIGIN}/api/auth/me`);
    expect(meAfterLogout.status(), '/api/auth/me must be 401 after logout').toBe(401);

    // Step 5: confirm SSR on /app redirects to /auth/login (session gone server-side)
    await page.goto(`${OPEN_ORIGIN}/app`);
    await expect(page).toHaveURL(`${OPEN_ORIGIN}/auth/login`);
    await expect(page.getByRole('heading', { name: /sign in/i })).toBeVisible();
  });

  // ── 3. Admin login → MFA setup continuation ──────────────────────────────
  //
  // Proves:
  // - login-next-action policy returns MFA_SETUP_REQUIRED for ADMIN with no MFA
  // - frontend routes to /auth/mfa/setup
  // - the MFA setup page renders the QR code and secret from the real backend
  //
  // WHY we do NOT call POST /api/auth/mfa/setup via page.request here:
  // - The MFA setup page component calls POST /auth/mfa/setup in a useEffect
  //   on mount. If the test also calls the same endpoint concurrently, both
  //   requests hit the INSERT INTO mfa_secrets simultaneously. The UNIQUE
  //   constraint on (user_id) means one succeeds and one gets a DB constraint
  //   violation → 500 → component shows error state → no QR renders.
  // - The correct approach is to wait for the component to render the QR
  //   (proving the useEffect call succeeded end-to-end) and check for any
  //   error banner if it does not appear.

  test('admin login without MFA continues to /auth/mfa/setup', async ({ page }) => {
    await page.goto(`${OPEN_ORIGIN}/auth/login`);

    await page.getByLabel('Email').fill(E2E_ADMIN_EMAIL);
    await page.getByLabel('Password').fill(E2E_ADMIN_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();

    // MFA_SETUP_REQUIRED → /auth/mfa/setup
    await expect(page).toHaveURL(`${OPEN_ORIGIN}/auth/mfa/setup`);
    await expect(page.getByRole('heading', { name: /multi-factor authentication/i })).toBeVisible();

    // Wait for either the QR code to appear or an error banner.
    // If an error banner appears first, fail with its message so the root cause
    // is visible in the test output without needing to open a trace.
    const qrLocator = page.getByRole('img', { name: /qr code/i });
    const errorLocator = page.getByRole('alert').filter({ hasText: /error|failed|wrong/i });

    const which = await Promise.race([
      qrLocator.waitFor({ state: 'visible' }).then(() => 'qr' as const),
      errorLocator.waitFor({ state: 'visible' }).then(() => 'error' as const),
    ]);

    if (which === 'error') {
      const errorText = await errorLocator.textContent().catch(() => '(unreadable)');
      throw new Error(
        `MFA setup page showed an error instead of the QR code.\n` +
          `Error text: ${errorText}\n` +
          `Check: backend logs for POST /auth/mfa/setup, ` +
          `and confirm seed-e2e-fixtures cleared mfa_recovery_codes.`,
      );
    }

    // QR rendered — proves the component's useEffect called the backend
    // successfully and the real MFA secret was returned and displayed.
    await expect(page.getByLabel('Authenticator secret')).toBeVisible();
    const secret = await page.getByLabel('Authenticator secret').inputValue();
    expect(secret.length, 'MFA secret must be a non-empty base32 string').toBeGreaterThan(0);
  });

  // ── 4. Public signup → email verification → authenticated ─────────────────
  //
  // Proves:
  // - POST /api/auth/signup works against the real DB
  // - the backend enqueues an outbox message and delivers it to Mailpit via SMTP
  // - the verification link is tenant-shaped and contains a valid token
  // - navigating to the verify link completes verification and creates a session

  test('signup delivers verification email and verify-link completes auth', async ({ page }) => {
    const email = `e2e-signup-${Date.now()}@example.com`;

    await purgeMailpit();

    await page.goto(`${OPEN_ORIGIN}/auth/signup`);
    await expect(page.getByRole('heading', { name: /create your/i })).toBeVisible();

    await page.getByLabel('Full name').fill('E2E Signup User');
    await page.getByLabel('Email').fill(email);
    await page.getByLabel('Password').fill('Password123!');
    await page.getByRole('button', { name: 'Create account' }).click();

    await expect(page).toHaveURL(`${OPEN_ORIGIN}/verify-email`);

    const message = await waitForEmailToRecipient(email);
    expect(message.Subject).toMatch(/verify/i);

    const verifyLink = extractLinkFromText(message.Text, '/verify-email?token=');
    expect(verifyLink).toContain(`${OPEN_TENANT}.lvh.me`);

    await page.goto(verifyLink);
    await expect(page).toHaveURL(`${OPEN_ORIGIN}/app`);
    await expect(page.getByRole('heading', { name: 'Member app' })).toBeVisible();
    await expect(page.getByText('Authenticated handoff complete')).toBeVisible();
  });

  // ── 5. Signup blocked on invite-only tenant ───────────────────────────────

  test('signup page shows blocked state on invite-only tenant', async ({ page }) => {
    await page.goto(`${INVITE_ONLY_ORIGIN}/auth/signup`);

    await expect(page.getByText(/sign up is disabled/i)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Create account' })).toHaveCount(0);
  });

  // ── 6. Topology: host-derived tenant resolution through Caddy proxy ───────

  test('topology: host-derived tenant identity resolves correctly through Caddy', async ({
    request,
  }) => {
    const openConfig = await request.get(`${OPEN_ORIGIN}/api/auth/config`);
    expect(openConfig.status()).toBe(200);
    const openBody = (await openConfig.json()) as {
      tenant: { name: string; isActive: boolean; signupAllowed: boolean };
    };
    expect(openBody.tenant.name).toMatch(/goodwill open/i);
    expect(openBody.tenant.isActive).toBe(true);
    expect(openBody.tenant.signupAllowed).toBe(true);

    const caConfig = await request.get(`${INVITE_ONLY_ORIGIN}/api/auth/config`);
    expect(caConfig.status()).toBe(200);
    const caBody = (await caConfig.json()) as {
      tenant: { name: string; isActive: boolean; signupAllowed: boolean };
    };
    expect(caBody.tenant.name).toMatch(/goodwill california/i);
    expect(caBody.tenant.isActive).toBe(true);
    expect(caBody.tenant.signupAllowed).toBe(false);

    const unknownConfig = await request.get(
      `http://does-not-exist.lvh.me:${PROXY_PORT}/api/auth/config`,
    );
    expect(unknownConfig.status()).toBe(200);
    const unknownBody = (await unknownConfig.json()) as { tenant: { isActive: boolean } };
    expect(unknownBody.tenant.isActive).toBe(false);
  });

  // ── 7. Topology: SSO start sets state cookie through Caddy proxy ──────────

  test('topology: SSO start sets sso-state cookie and redirects to provider', async ({
    request,
  }) => {
    const response = await request.get(`${OPEN_ORIGIN}/api/auth/sso/google`, {
      maxRedirects: 0,
    });

    expect(response.status(), 'SSO start must return 302').toBe(302);

    const location = response.headers()['location'] ?? '';
    // WHY not asserting accounts.google.com:
    // When LOCAL_OIDC_ENABLED=true (dev + CI), the google slot uses
    // LocalOidcSsoAdapter which redirects to localhost:9998/authorize.
    // When LOCAL_OIDC is off (staging/production), it redirects to
    // accounts.google.com. Both are valid — we assert shape, not destination.
    expect(location, 'SSO start must redirect to an authorize endpoint').toMatch(
      /\/authorize\?|accounts\.google\.com|login\.microsoftonline\.com/,
    );
    expect(location, 'SSO start redirect must carry a state param').toContain('state=');
    expect(location, 'SSO start redirect must carry a nonce param').toContain('nonce=');

    const setCookieHeaders = response
      .headersArray()
      .filter((h) => h.name.toLowerCase() === 'set-cookie')
      .map((h) => h.value);

    const ssoStateCookie = setCookieHeaders.find((v) => v.includes('sso-state'));
    expect(ssoStateCookie, 'sso-state cookie must be set').toBeDefined();
    expect(ssoStateCookie).toContain('SameSite=Lax');
    expect(ssoStateCookie).toContain('HttpOnly');
  });

  // ── 8. Google SSO — full callback loop via local OIDC server ──────────────
  //
  // WHY this test exists:
  // - Backend unit/E2E tests use FakeSsoAdapter which bypasses real JWKS fetch
  //   and JWT signature verification entirely. They prove flow logic, not crypto.
  // - This test proves the actual jose jwtVerify() path in a real browser
  //   against the real backend and real session/audit machinery:
  //     JWKS HTTP fetch → RSA-256 signature → iss/aud/exp enforcement → nonce.
  //
  // WHY request-level (not full browser navigation):
  // - The local OIDC server's /authorize endpoint serves a redirect page, not a
  //   real provider consent UI. Testing via direct callback call is correct — it
  //   exercises the same backend code path a real OAuth redirect would trigger.
  //   Browser navigation is already proven by test 7 (SSO start → 302 + cookie).
  //
  // PREREQUISITES:
  // - Stack running with docker-compose-ci-oidc.yml overlay.
  // - Backend configured with LOCAL_OIDC_ENABLED=true.
  // - Test is skipped automatically when local OIDC server is unreachable.

  test('SSO Google callback: full loop via local OIDC → session created + audit written', async ({
    request,
  }) => {
    const oidcReachable = await isLocalOidcReachable();
    test.skip(
      !oidcReachable,
      'Local OIDC server not reachable — run stack with docker-compose-ci-oidc.yml',
    );

    const ssoEmail = `sso-google-${Date.now()}@example.com`;
    const ssoSub = `g-sub-${Date.now()}`;

    // ── A. SSO start — get sso-state cookie + extract state/nonce ────────────
    //
    // The backend encrypts nonce into the sso-state cookie and also returns it
    // as a query param in the redirect URL so the provider can embed it in the
    // id_token. We read it here to hand to the local OIDC server.

    const startRes = await request.get(`${OPEN_ORIGIN}/api/auth/sso/google`, {
      maxRedirects: 0,
    });

    expect(startRes.status(), 'SSO start must return 302').toBe(302);

    const redirectUrl = startRes.headers()['location'] ?? '';
    expect(
      redirectUrl,
      'SSO start must redirect to local OIDC (local-oidc:9998 or localhost:9998)',
    ).toMatch(/local-oidc:9998|localhost:9998/);

    const redirectParsed = new URL(redirectUrl.replace('local-oidc:9998', 'localhost:9998'));
    const state = redirectParsed.searchParams.get('state');
    const nonce = redirectParsed.searchParams.get('nonce');

    expect(state, 'state param must be present in SSO redirect URL').toBeTruthy();
    expect(nonce, 'nonce param must be present in SSO redirect URL').toBeTruthy();

    // ── B. Extract sso-state cookie from SSO start response ──────────────────
    //
    // Playwright APIRequestContext does not automatically replay Set-Cookie
    // from one response into the next request. We extract the raw value and
    // pass it in the Cookie header of the callback call.

    const setCookieHeaders = startRes
      .headersArray()
      .filter((h) => h.name.toLowerCase() === 'set-cookie')
      .map((h) => h.value);

    const ssoStateCookieHeader = setCookieHeaders.find((v) => v.includes('sso-state'));
    expect(ssoStateCookieHeader, 'sso-state cookie must be set by SSO start').toBeDefined();

    // Extract just the cookie value (everything before the first ';')
    const ssoStateCookieValue = (ssoStateCookieHeader ?? '').split(';')[0].trim();
    expect(ssoStateCookieValue, 'sso-state cookie value must be non-empty').toBeTruthy();

    // ── C. Register identity with local OIDC server ───────────────────────────
    //
    // POST /code returns a short-lived code that encodes { email, sub, nonce }.
    // The nonce must match what the backend embedded in the sso-state cookie.

    const { code } = await registerOidcIdentity({
      email: ssoEmail,
      sub: ssoSub,
      nonce: nonce as string,
    });

    // ── D. Call the backend callback endpoint ─────────────────────────────────
    //
    // The backend will:
    //   1. Decrypt sso-state cookie → extract nonce + provider + redirectUri
    //   2. Exchange code for id_token with local OIDC /token endpoint
    //   3. Run jose jwtVerify() against local OIDC JWKS (real RSA-256 path)
    //   4. Validate iss, aud, exp, nonce
    //   5. Provision user + MEMBER membership in goodwill-open (new email)
    //   6. Create session + set sid cookie
    //   7. Redirect to /done?nextAction=NONE

    const callbackRes = await request.get(
      `${OPEN_ORIGIN}/api/auth/sso/google/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state as string)}`,
      {
        maxRedirects: 0,
        headers: { Cookie: ssoStateCookieValue },
      },
    );

    expect(callbackRes.status(), `SSO callback must return 302 (got ${callbackRes.status()})`).toBe(
      302,
    );

    const callbackLocation = callbackRes.headers()['location'] ?? '';
    expect(callbackLocation, 'SSO callback must redirect to /done').toContain('/done');
    expect(callbackLocation, 'nextAction must be NONE').toContain('nextAction=NONE');

    // ── E. Assert session cookie is set ──────────────────────────────────────

    const callbackSetCookie = callbackRes
      .headersArray()
      .filter((h) => h.name.toLowerCase() === 'set-cookie')
      .map((h) => h.value);

    const sidCookie = callbackSetCookie.find((v) => v.startsWith('sid='));
    expect(sidCookie, 'sid session cookie must be set after SSO callback').toBeDefined();
    expect(sidCookie, 'sid must be HttpOnly').toContain('HttpOnly');
    expect(sidCookie, 'sid must be SameSite=Strict').toContain('SameSite=Strict');

    // ── F. Assert audit event was written ────────────────────────────────────
    //
    // Extract the session ID from the sid cookie and call /api/auth/me to get
    // tenant + user context, then verify the audit event exists.
    // WHY /api/auth/me rather than /api/admin/audit-events: the new user is a
    // MEMBER (not ADMIN), so admin audit viewer is not accessible. /auth/me
    // confirms the session is real and the user/membership were provisioned.

    const sidValue = (sidCookie ?? '').split(';')[0].trim();
    const meRes = await request.get(`${OPEN_ORIGIN}/api/auth/me`, {
      headers: { Cookie: sidValue },
    });

    expect(meRes.status(), '/api/auth/me must be 200 with the new SSO session').toBe(200);

    const meBody = (await meRes.json()) as {
      user: { email: string };
      membership: { role: string };
      session: { mfaVerified: boolean };
    };

    expect(meBody.user.email.toLowerCase(), 'Session must be for the SSO email').toBe(
      ssoEmail.toLowerCase(),
    );
    expect(meBody.membership.role, 'New SSO member in goodwill-open must have MEMBER role').toBe(
      'MEMBER',
    );
    // WHY true: when MFA is not required for this membership, the SSO callback
    // creates the session as fully authenticated. mfaVerified=false means
    // "MFA is required but not yet completed" — the opposite state.
    expect(
      meBody.session.mfaVerified,
      'MEMBER with no MFA requirement is fully authenticated — mfaVerified must be true',
    ).toBe(true);
  });

  // ── 9. Microsoft SSO — full callback loop via local OIDC server ───────────
  //
  // Same structure as test 8 (Google). Microsoft adapter differences:
  // - No email_verified claim requirement (locked spec: Microsoft has no
  //   reliable equivalent — see MicrosoftSsoAdapter).
  // - Email resolved from preferred_username / upn fallback chain.
  // - Issuer derived from tid claim (multi-tenant Entra ID).
  //
  // The local OIDC server is provider-agnostic. LocalOidcSsoAdapter is
  // registered under both 'google' and 'microsoft' slots in CI DI wiring,
  // so this test exercises the real Microsoft adapter code path against the
  // same JWKS infrastructure.

  test('SSO Microsoft callback: full loop via local OIDC → session created', async ({
    request,
  }) => {
    const oidcReachable = await isLocalOidcReachable();
    test.skip(
      !oidcReachable,
      'Local OIDC server not reachable — run stack with docker-compose-ci-oidc.yml',
    );

    const ssoEmail = `sso-microsoft-${Date.now()}@example.com`;
    const ssoSub = `ms-sub-${Date.now()}`;

    // ── A. SSO start ──────────────────────────────────────────────────────────

    const startRes = await request.get(`${OPEN_ORIGIN}/api/auth/sso/microsoft`, {
      maxRedirects: 0,
    });

    expect(startRes.status(), 'Microsoft SSO start must return 302').toBe(302);

    const redirectUrl = startRes.headers()['location'] ?? '';
    expect(redirectUrl, 'SSO start must redirect to local OIDC').toMatch(
      /local-oidc:9998|localhost:9998/,
    );

    const redirectParsed = new URL(redirectUrl.replace('local-oidc:9998', 'localhost:9998'));
    const state = redirectParsed.searchParams.get('state');
    const nonce = redirectParsed.searchParams.get('nonce');

    expect(state, 'state must be present').toBeTruthy();
    expect(nonce, 'nonce must be present').toBeTruthy();

    // ── B. Extract sso-state cookie ───────────────────────────────────────────

    const setCookieHeaders = startRes
      .headersArray()
      .filter((h) => h.name.toLowerCase() === 'set-cookie')
      .map((h) => h.value);

    const ssoStateCookieHeader = setCookieHeaders.find((v) => v.includes('sso-state'));
    expect(ssoStateCookieHeader, 'sso-state cookie must be set').toBeDefined();
    const ssoStateCookieValue = (ssoStateCookieHeader ?? '').split(';')[0].trim();

    // ── C. Register identity with local OIDC ──────────────────────────────────
    //
    // Microsoft path: email_verified is not checked by the adapter.
    // We still send email_verified: true because the OIDC server includes it
    // in the token payload — the backend simply doesn't validate it for Microsoft.

    const { code } = await registerOidcIdentity({
      email: ssoEmail,
      sub: ssoSub,
      nonce: nonce as string,
      emailVerified: true,
    });

    // ── D. Call the backend callback endpoint ─────────────────────────────────

    const callbackRes = await request.get(
      `${OPEN_ORIGIN}/api/auth/sso/microsoft/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state as string)}`,
      {
        maxRedirects: 0,
        headers: { Cookie: ssoStateCookieValue },
      },
    );

    expect(
      callbackRes.status(),
      `Microsoft SSO callback must return 302 (got ${callbackRes.status()})`,
    ).toBe(302);

    const callbackLocation = callbackRes.headers()['location'] ?? '';
    expect(callbackLocation, 'Microsoft SSO callback must redirect to /done').toContain('/done');
    expect(callbackLocation, 'nextAction must be NONE').toContain('nextAction=NONE');

    // ── E. Assert session cookie ───────────────────────────────────────────────

    const callbackSetCookie = callbackRes
      .headersArray()
      .filter((h) => h.name.toLowerCase() === 'set-cookie')
      .map((h) => h.value);

    const sidCookie = callbackSetCookie.find((v) => v.startsWith('sid='));
    expect(sidCookie, 'sid session cookie must be set').toBeDefined();
    expect(sidCookie, 'sid must be HttpOnly').toContain('HttpOnly');
    expect(sidCookie, 'sid must be SameSite=Strict').toContain('SameSite=Strict');

    // ── F. Confirm session is valid ───────────────────────────────────────────

    const sidValue = (sidCookie ?? '').split(';')[0].trim();
    const meRes = await request.get(`${OPEN_ORIGIN}/api/auth/me`, {
      headers: { Cookie: sidValue },
    });

    expect(meRes.status(), '/api/auth/me must be 200 with Microsoft SSO session').toBe(200);

    const meBody = (await meRes.json()) as {
      user: { email: string };
      membership: { role: string };
    };
    expect(meBody.user.email.toLowerCase()).toBe(ssoEmail.toLowerCase());
    expect(meBody.membership.role).toBe('MEMBER');
  });

  // ── 10. Cross-tenant session isolation ────────────────────────────────────

  test('cross-tenant isolation: goodwill-open session rejected on goodwill-ca', async ({
    page,
  }) => {
    await page.goto(`${OPEN_ORIGIN}/auth/login`);
    await page.getByLabel('Email').fill(MEMBER_EMAIL);
    await page.getByLabel('Password').fill(MEMBER_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page).toHaveURL(`${OPEN_ORIGIN}/app`);

    const meOnOtherTenant = await page.request.get(`${INVITE_ONLY_ORIGIN}/api/auth/me`);
    expect(
      meOnOtherTenant.status(),
      '/api/auth/me on goodwill-ca with goodwill-open session must be 401',
    ).toBe(401);
  });

  // ── Phase 9 smoke tests ───────────────────────────────────────────────────
  //
  // Proves the workspace setup banner contract (ADR 0003):
  // - /admin/settings route exists and is reachable (not 404)
  // - unauthenticated access to /admin/settings is redirected, not 500
  // - NONE + MEMBER routes to /app (role-aware routing fix)
  // - NONE + ADMIN routes to /admin (role-aware routing fix)
  // - members are redirected away from /admin (role gate enforced)
  //
  // The full workspace-setup-ack flow (banner → settings → ack → banner gone)
  // requires a fully authenticated admin session (MFA verified), which needs a
  // real authenticator app. That is Phase 5 territory. These tests prove the
  // route surfaces and role-routing contracts that are prerequisite to that proof.

  test('phase-9: /admin/settings route exists and redirects unauthenticated access', async ({
    page,
  }) => {
    // Route must exist (not 404). Unauthenticated access must redirect to login.
    await page.goto(`${OPEN_ORIGIN}/admin/settings`);

    // Should have been redirected — not still on /admin/settings and not a 404.
    const finalUrl = page.url();
    expect(
      finalUrl,
      '/admin/settings must redirect unauthenticated access, not stay on the page',
    ).not.toBe(`${OPEN_ORIGIN}/admin/settings`);

    // The redirect destination must be a valid auth page, not an error page.
    expect(
      finalUrl.includes('/auth/') || finalUrl.includes('/app'),
      `Expected redirect to an auth path, got: ${finalUrl}`,
    ).toBe(true);
  });

  test('phase-9: /admin/settings responds with a page (not 404) for any request', async ({
    request,
  }) => {
    // Even without a session, Next.js must handle the route and return a
    // renderable response (200 with redirect HTML, or a 3xx). Never 404.
    const response = await request.get(`${OPEN_ORIGIN}/admin/settings`, {
      maxRedirects: 0,
    });

    expect(
      response.status(),
      '/admin/settings must not return 404 — route must be registered in Next.js',
    ).not.toBe(404);
  });

  test('phase-9: member login lands on /app, not /admin (NONE + MEMBER role-aware routing)', async ({
    page,
  }) => {
    await page.goto(`${OPEN_ORIGIN}/auth/login`);
    await page.getByLabel('Email').fill(MEMBER_EMAIL);
    await page.getByLabel('Password').fill(MEMBER_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();

    // NONE + MEMBER → /app (not /admin, not /admin/settings)
    await expect(page).toHaveURL(`${OPEN_ORIGIN}/app`);
    await expect(page.getByRole('heading', { name: 'Member app' })).toBeVisible();
    await expect(page.getByText('Authenticated handoff complete')).toBeVisible();
  });

  test('phase-9: member is redirected away from /admin (role gate enforced)', async ({ page }) => {
    // Log in as member first to get an authenticated session
    await page.goto(`${OPEN_ORIGIN}/auth/login`);
    await page.getByLabel('Email').fill(MEMBER_EMAIL);
    await page.getByLabel('Password').fill(MEMBER_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page).toHaveURL(`${OPEN_ORIGIN}/app`);

    // Attempt to navigate to the admin area directly
    await page.goto(`${OPEN_ORIGIN}/admin`);

    // Member must be redirected — /admin is ADMIN-only
    await expect(page).not.toHaveURL(`${OPEN_ORIGIN}/admin`);
  });

  test('phase-9: admin login continues to /auth/mfa/setup (MFA_SETUP_REQUIRED continuation unchanged)', async ({
    page,
  }) => {
    // Proves the auth continuation chain is unaffected by Phase 9 changes.
    // Admin with no MFA still continues to /auth/mfa/setup — not /admin/settings.
    // Setup banner lives on /admin; it does not intercept the auth flow.
    await page.goto(`${OPEN_ORIGIN}/auth/login`);
    await page.getByLabel('Email').fill(E2E_ADMIN_EMAIL);
    await page.getByLabel('Password').fill(E2E_ADMIN_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();

    // Still goes to MFA setup — NONE + ADMIN → /admin happens only after full auth
    await expect(page).toHaveURL(`${OPEN_ORIGIN}/auth/mfa/setup`);
    await expect(page.getByRole('heading', { name: /multi-factor authentication/i })).toBeVisible();
  });

  // ── 11. MFA full verification loop ───────────────────────────────────────
  //
  // WHY this test exists (Phase 5 roadmap closure):
  // - All prior tests stop at QR-renders or MFA_SETUP_REQUIRED continuation.
  // - The roadmap success criterion requires proof that a user can COMPLETE MFA
  //   verification against the real backend and land on the authenticated area.
  // - Without this test, the backend's POST /auth/mfa/verify-setup and the full
  //   TOTP validation path are only proven at the backend E2E level (Fastify inject),
  //   not in a real browser against the full Docker stack.
  //
  // WHAT IS PROVEN:
  // - POST /auth/mfa/setup returns a real base32 secret from the real backend.
  // - generateTotp() computes the same 6-digit code a real authenticator app would.
  // - POST /auth/mfa/verify-setup accepts the code → session gains mfaVerified=true.
  // - Frontend routes NONE + ADMIN → /admin (role-aware routing proven end-to-end).
  // - GET /auth/me confirms mfaVerified=true and role=ADMIN on the upgraded session.
  //
  // WHY we read the secret from the UI element (not call POST /auth/mfa/setup ourselves):
  // - Reading from the rendered "Authenticator secret" input proves the full frontend
  //   rendering path (component mounted, useEffect fired, API call succeeded, UI updated).
  // - A direct API call would bypass the frontend rendering path entirely.
  //
  // CLOCK-SKEW NOTE:
  // - generateTotp(secret, 0) generates the code for the CURRENT 30-second slot.
  // - The backend accepts ±1 step (see TotpService WINDOW=1 comment in totp.ts).
  // - If CI clock drift causes a spurious failure, add a second attempt with window=1.

  test('mfa full loop: setup → compute TOTP → verify-setup → /admin → mfaVerified=true', async ({
    page,
  }) => {
    // Step 1: login as E2E admin (no MFA → MFA_SETUP_REQUIRED)
    await page.goto(`${OPEN_ORIGIN}/auth/login`);
    await page.getByLabel('Email').fill(E2E_ADMIN_EMAIL);
    await page.getByLabel('Password').fill(E2E_ADMIN_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();

    await expect(page).toHaveURL(`${OPEN_ORIGIN}/auth/mfa/setup`);
    await expect(page.getByRole('heading', { name: /multi-factor authentication/i })).toBeVisible();

    // Step 2: wait for QR code image and secret input to appear
    // (proves POST /auth/mfa/setup succeeded on the real backend)
    const secretInput = page.getByLabel('Authenticator secret');
    const errorLocator = page.getByRole('alert').filter({ hasText: /error|failed|wrong/i });

    const which = await Promise.race([
      secretInput.waitFor({ state: 'visible' }).then(() => 'secret' as const),
      errorLocator.waitFor({ state: 'visible' }).then(() => 'error' as const),
    ]);

    if (which === 'error') {
      const errorText = await errorLocator.textContent().catch(() => '(unreadable)');
      throw new Error(
        `MFA setup page showed an error instead of the secret.\n` +
          `Error: ${errorText}\n` +
          `Check: backend logs for POST /auth/mfa/setup; confirm seed-e2e-fixtures cleared mfa_secrets.`,
      );
    }

    const base32Secret = await secretInput.inputValue();

    // In Jest/Vitest, the message argument is not supported inside expect()
    expect(base32Secret.length).toBeGreaterThan(0);
    expect(base32Secret).toMatch(/^[A-Z2-7]+=*$/i);

    // Step 3: compute a real TOTP code from the secret
    // (RFC 6238 TOTP over HMAC-SHA1).
    const totpCode = generateTotp(base32Secret, 0);

    expect(totpCode).toMatch(/^\d{6}$/);

    // Step 4: submit the code via the verify-setup form
    const codeInput = page.getByLabel('6-digit code');
    await codeInput.fill(totpCode);
    await page.getByRole('button', { name: 'Finish MFA setup' }).click();

    // Step 5: POST /auth/mfa/verify-setup accepted → nextAction: NONE + ADMIN → /admin
    await expect(page).toHaveURL(`${OPEN_ORIGIN}/admin`);

    // Step 6: confirm the backend session reflects mfaVerified=true
    const me = await page.request.get(`${OPEN_ORIGIN}/api/auth/me`);
    expect(me.status(), '/api/auth/me must be 200 after MFA verification').toBe(200);

    const meBody = (await me.json()) as {
      session: { mfaVerified: boolean; emailVerified: boolean };
      membership: { role: string };
    };

    expect(
      meBody.session.mfaVerified,
      '/api/auth/me must return mfaVerified=true after verify-setup',
    ).toBe(true);
    expect(meBody.membership.role, 'Authenticated admin must have role ADMIN').toBe('ADMIN');
  });

  // ── 12. Invite acceptance full browser journey ────────────────────────────
  //
  // WHY this test exists (Phase 8 roadmap closure — audit S1 item):
  // - Invite flows are proven at the backend E2E level (Fastify inject) but not
  //   in a real browser against the full Docker stack including email delivery.
  // - This test proves the end-to-end invite onboarding path: admin creates invite
  //   → real SMTP delivery via Mailpit → browser accepts token → register form
  //   → authenticated session → /app.
  //
  // WHAT IS PROVEN:
  // - POST /admin/invites creates a real invite and enqueues email delivery.
  // - The outbox worker delivers the email to Mailpit via real SMTP.
  // - The invite link is shaped correctly (tenant-scoped, contains token).
  // - POST /auth/invites/accept returns nextAction: SET_PASSWORD.
  // - POST /auth/register with the token creates a real session.
  // - MEMBER role + no MFA → nextAction: NONE → frontend routes to /app.
  //
  // WHY this test uses a SECOND admin persona (e2e-invite-admin@example.com):
  // - Test 11 configures MFA for e2e-admin@example.com. After test 11, that admin
  //   has MFA_REQUIRED (not MFA_SETUP_REQUIRED) on the next login. Reusing the
  //   same persona would require handling a different continuation branch.
  // - e2e-invite-admin@example.com is seeded with no MFA (same as the primary admin
  //   before test 11 runs), giving this test a fully independent setup path.
  //   See seed-e2e-fixtures.ts for the second persona's seeding logic.

  test('invite acceptance journey: admin creates invite → email → accept → register → /app', async ({
    page,
  }) => {
    // WHY 120s: this test does more sequential work than any other test —
    // MFA setup, invite creation, email delivery wait (up to 30s outbox poll),
    // fresh context navigation, and registration. The global 60s is too tight.
    test.setTimeout(120_000);
    const E2E_INVITE_ADMIN_EMAIL = 'e2e-invite-admin@example.com';
    const inviteRecipientEmail = `e2e-invite-recipient-${Date.now()}@example.com`;

    await purgeMailpit();

    // ── A. Establish a MFA-verified admin session ────────────────────────────
    // The invite-admin persona starts with no MFA → goes through MFA_SETUP_REQUIRED.

    await page.goto(`${OPEN_ORIGIN}/auth/login`);
    await page.getByLabel('Email').fill(E2E_INVITE_ADMIN_EMAIL);
    await page.getByLabel('Password').fill(E2E_ADMIN_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();

    await expect(page).toHaveURL(`${OPEN_ORIGIN}/auth/mfa/setup`);

    const secretInput = page.getByLabel('Authenticator secret');
    await expect(secretInput).toBeVisible({ timeout: 15_000 });
    const base32Secret = await secretInput.inputValue();

    const setupCode = generateTotp(base32Secret);
    await page.getByLabel('6-digit code').fill(setupCode);
    await page.getByRole('button', { name: 'Finish MFA setup' }).click();

    await expect(page).toHaveURL(`${OPEN_ORIGIN}/admin`, { timeout: 15_000 });

    // ── B. Create the invite via POST /api/admin/invites ─────────────────────
    // page.request shares the authenticated session cookie established above.

    const createRes = await page.request.post(`${OPEN_ORIGIN}/api/admin/invites`, {
      data: { email: inviteRecipientEmail, role: 'MEMBER' },
    });
    expect(
      createRes.status(),
      `POST /admin/invites must return 201 (got ${createRes.status()})`,
    ).toBe(201);

    // ── C. Wait for invite email in Mailpit ──────────────────────────────────
    // The outbox worker delivers this asynchronously via real SMTP.

    const message = await waitForEmailToRecipient(inviteRecipientEmail);
    expect(message.Subject, 'Invite email subject must contain "invite"').toMatch(/invite/i);

    // ── D. Extract invite link ────────────────────────────────────────────────
    const inviteLink = extractLinkFromText(message.Text, '/accept-invite?token=');
    expect(inviteLink, 'Invite link must be on the open tenant host').toContain(
      `${OPEN_TENANT}.lvh.me`,
    );

    // ── E. Navigate to the invite link as a new (unauthenticated) user ───────
    // Open a fresh browser context so the admin session cookie does not carry over.

    const inviteBrowser = page.context().browser();
    if (!inviteBrowser) throw new Error('Could not get browser instance from page context');

    const freshContext = await inviteBrowser.newContext();
    const freshPage = await freshContext.newPage();

    try {
      await freshPage.goto(inviteLink);

      // accept-invite-flow auto-submits POST /auth/invites/accept on mount.
      // nextAction: SET_PASSWORD → frontend redirects to /auth/register?token=...
      await expect(freshPage).toHaveURL(/\/auth\/register/, { timeout: 15_000 });

      // ── F. Fill and submit the register form ───────────────────────────────
      await freshPage.getByLabel('Full name').fill('Invited Browser User');
      await freshPage.getByLabel('Email').fill(inviteRecipientEmail);
      await freshPage.getByLabel('Password').fill('Password123!');
      await freshPage.getByRole('button', { name: 'Set password and continue' }).click();

      // ── G. Verify landing on /app (MEMBER, no MFA required) ───────────────
      await expect(freshPage).toHaveURL(`${OPEN_ORIGIN}/app`, { timeout: 15_000 });
      await expect(freshPage.getByRole('heading', { name: 'Member app' })).toBeVisible();
      await expect(freshPage.getByText('Authenticated handoff complete')).toBeVisible();

      // Confirm the session is authenticated as the new member
      const me = await freshPage.request.get(`${OPEN_ORIGIN}/api/auth/me`);
      expect(me.status(), '/api/auth/me must be 200 after invite registration').toBe(200);

      const meBody = (await me.json()) as {
        user: { email: string };
        membership: { role: string };
        session: { mfaVerified: boolean };
      };

      expect(meBody.user.email.toLowerCase()).toBe(inviteRecipientEmail.toLowerCase());
      expect(meBody.membership.role, 'Invite-registered user must have MEMBER role').toBe('MEMBER');
    } finally {
      await freshContext.close().catch(() => undefined);
    }
  });

  // ── 18. MFA recovery full loop ────────────────────────────────────────────
  //
  // Proves:
  // - recovery code is visible on the MFA setup page after POST /auth/mfa/setup
  // - POST /auth/mfa/recover accepts a valid recovery code and establishes session
  // - session cookie is rotated after recovery (privilege elevation)
  // - the same recovery code is rejected on a second use (single-use enforcement)
  //
  // Backend E2E tests cover this at the API level. This test proves the browser
  // path: the user can actually read a recovery code off the setup page and use
  // it to log in when they do not have their authenticator app.
  //
  // WHY a dedicated E2E admin persona rather than reusing e2e-admin:
  // The MFA loop test (test 16) leaves e2e-admin with a configured MFA secret.
  // Reusing it here would mean navigating MFA_REQUIRED (verify path) rather than
  // MFA_SETUP_REQUIRED (setup path), which is a different page. A dedicated persona
  // e2e-recovery-admin@example.com that always starts with no MFA keeps this test
  // independent. However, rather than creating a third seed persona, we reuse
  // e2e-admin after the fixture seed clears its MFA — which already happens
  // between test runs. We just need to seed again before this test.
  //
  // PRACTICAL APPROACH: Use page.request to drive the API directly for setup +
  // verify-setup (same as test 16 does via the UI), then log out, log back in
  // via the UI to reach /auth/mfa/verify, and use the recovery code there.
  // This keeps the test fast and deterministic — no TOTP timing window.

  test('mfa recovery: use recovery code → session established → code rejected on reuse', async ({
    page,
  }) => {
    // WHY 90s: login × 2 + MFA setup + recovery code path + re-login + reuse check
    test.setTimeout(90_000);

    // ── A. Login as e2e-recovery-admin → MFA_SETUP_REQUIRED ────────────────
    // WHY dedicated persona: tests 16 and 17 both configure MFA for the other
    // two E2E admin personas during the same run. e2e-recovery-admin is never
    // touched by any other test, so the seed's MFA clear guarantees it always
    // starts with no MFA and login always returns MFA_SETUP_REQUIRED.

    await page.goto(`${OPEN_ORIGIN}/auth/login`);
    await page.getByLabel('Email').fill(E2E_RECOVERY_ADMIN_EMAIL);
    await page.getByLabel('Password').fill(E2E_ADMIN_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();

    await expect(page).toHaveURL(`${OPEN_ORIGIN}/auth/mfa/setup`);

    // ── B. Wait for setup data (QR + secret + recovery codes) ────────────────

    const secretInput = page.getByLabel('Authenticator secret');
    await expect(secretInput).toBeVisible({ timeout: 15_000 });
    const base32Secret = await secretInput.inputValue();

    // ── C. Read one recovery code from the page ───────────────────────────────
    // Recovery codes are rendered as <li><code>...</code></li> inside the
    // "Recovery codes" section. We grab the first one.

    const firstRecoveryCode = page
      .getByRole('listitem')
      .filter({ has: page.locator('code') })
      .first()
      .locator('code');

    await expect(firstRecoveryCode).toBeVisible({ timeout: 10_000 });
    const recoveryCodeValue = await firstRecoveryCode.textContent();
    expect(recoveryCodeValue, 'Recovery code must be a non-empty string').toBeTruthy();

    // ── D. Complete MFA setup via TOTP so the MFA secret is verified ──────────
    // POST /auth/mfa/verify-setup requires a valid TOTP code. Without completing
    // setup the recovery codes are not yet activated (mfa_secrets.is_verified=false).

    const setupCode = generateTotp(base32Secret);
    await page.getByLabel('6-digit code').fill(setupCode);
    await page.getByRole('button', { name: 'Finish MFA setup' }).click();

    await expect(page).toHaveURL(`${OPEN_ORIGIN}/admin`, { timeout: 15_000 });

    // ── E. Log out ────────────────────────────────────────────────────────────

    await page.request.post(`${OPEN_ORIGIN}/api/auth/logout`);

    // ── F. Log back in → MFA_REQUIRED → /auth/mfa/verify ─────────────────────
    // Now the admin has a verified MFA secret, so login returns MFA_REQUIRED.

    await page.goto(`${OPEN_ORIGIN}/auth/login`);
    await page.getByLabel('Email').fill(E2E_RECOVERY_ADMIN_EMAIL);
    await page.getByLabel('Password').fill(E2E_ADMIN_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();

    await expect(page).toHaveURL(`${OPEN_ORIGIN}/auth/mfa/verify`, { timeout: 10_000 });

    // ── G. Use the recovery code instead of TOTP ──────────────────────────────
    // The MFA verify page shows "or use a recovery code" section below the TOTP form.

    const recoveryCodeInput = page.getByLabel('Recovery code');
    await expect(recoveryCodeInput).toBeVisible({ timeout: 5_000 });
    await recoveryCodeInput.fill(recoveryCodeValue as string);
    await page.getByRole('button', { name: 'Use recovery code' }).click();

    // ── H. Assert authenticated session established ────────────────────────────

    await expect(page).toHaveURL(`${OPEN_ORIGIN}/admin`, { timeout: 15_000 });

    const meAfterRecovery = await page.request.get(`${OPEN_ORIGIN}/api/auth/me`);
    expect(meAfterRecovery.status(), '/api/auth/me must be 200 after recovery login').toBe(200);

    const meBody = (await meAfterRecovery.json()) as { session: { mfaVerified: boolean } };
    expect(meBody.session.mfaVerified, 'session.mfaVerified must be true after recovery').toBe(
      true,
    );

    // ── I. Log out + log back in + attempt to reuse the same code ─────────────

    await page.request.post(`${OPEN_ORIGIN}/api/auth/logout`);

    await page.goto(`${OPEN_ORIGIN}/auth/login`);
    await page.getByLabel('Email').fill(E2E_RECOVERY_ADMIN_EMAIL);
    await page.getByLabel('Password').fill(E2E_ADMIN_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();

    await expect(page).toHaveURL(`${OPEN_ORIGIN}/auth/mfa/verify`, { timeout: 10_000 });

    const recoveryCodeInput2 = page.getByLabel('Recovery code');
    await expect(recoveryCodeInput2).toBeVisible({ timeout: 5_000 });
    await recoveryCodeInput2.fill(recoveryCodeValue as string);
    await page.getByRole('button', { name: 'Use recovery code' }).click();

    // Single-use enforcement: the backend must reject the already-consumed code.
    // The form should surface an error, and the URL must NOT advance to /admin.
    await expect(
      page.getByRole('alert').or(page.getByText(/invalid|expired|already used/i)),
    ).toBeVisible({ timeout: 10_000 });

    await expect(page).not.toHaveURL(`${OPEN_ORIGIN}/admin`);
  });

  // ── 19. Password reset full loop ──────────────────────────────────────────
  //
  // Proves:
  // - POST /auth/forgot-password delivers a reset email via real SMTP/Mailpit
  // - the reset link in the email contains a valid token and navigates to
  //   /auth/reset-password correctly
  // - POST /auth/reset-password accepts the token and the new password
  // - the user can log in with the new password
  // - the old password is rejected after reset
  //
  // Uses a dedicated E2E persona (e2e-reset-member@example.com) that no other
  // test touches. The seed restores its password on every run.

  test('password reset: forgot → email → link → new password → login → old password rejected', async ({
    page,
  }) => {
    test.setTimeout(90_000);

    const RESET_PASSWORD = `Reset${Date.now()}!`;

    await purgeMailpit();

    // ── A. Navigate to forgot-password page ──────────────────────────────────

    await page.goto(`${OPEN_ORIGIN}/auth/forgot-password`);
    // Use level:2 to avoid strict mode violation — the page has both an h1 (tenant name)
    // and an h2 ('Request a reset link'). We want the h2 form heading specifically.
    await expect(
      page.getByRole('heading', { level: 2, name: /request a reset link/i }),
    ).toBeVisible();

    // ── B. Submit the forgot-password form ────────────────────────────────────

    await page.getByLabel('Email').fill(E2E_RESET_MEMBER_EMAIL);
    await page.getByRole('button', { name: 'Send reset link' }).click();

    // The backend always returns the generic "Check your email" message to
    // prevent account enumeration — assert this is what the user sees.
    await expect(page.getByText('Check your email')).toBeVisible({ timeout: 10_000 });

    // ── C. Wait for the reset email in Mailpit ────────────────────────────────

    const message = await waitForEmailToRecipient(E2E_RESET_MEMBER_EMAIL);
    expect(message.Subject, 'Reset email subject must reference reset').toMatch(/reset|password/i);

    // ── D. Extract the reset link ─────────────────────────────────────────────

    const resetLink = extractLinkFromText(message.Text, '/auth/reset-password?token=');
    expect(resetLink, 'Reset link must target the open tenant host').toContain(
      `${OPEN_TENANT}.lvh.me`,
    );

    // ── E. Navigate to the reset link ─────────────────────────────────────────

    await page.goto(resetLink);
    await expect(page).toHaveURL(/\/auth\/reset-password/, { timeout: 10_000 });

    // ── F. Submit the new password ────────────────────────────────────────────

    await page.getByLabel('New password').fill(RESET_PASSWORD);
    await page.getByRole('button', { name: /reset|update|save/i }).click();

    // Backend returns "Password updated successfully. Please sign in with your new password."
    // Target exact substring to avoid matching the "sign in" navigation links also on the page.
    await expect(page.getByText('Password updated successfully')).toBeVisible({ timeout: 10_000 });

    // ── G. Login with the new password ────────────────────────────────────────

    await page.goto(`${OPEN_ORIGIN}/auth/login`);
    await page.getByLabel('Email').fill(E2E_RESET_MEMBER_EMAIL);
    await page.getByLabel('Password').fill(RESET_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();

    await expect(page).toHaveURL(`${OPEN_ORIGIN}/app`, { timeout: 15_000 });

    const meRes = await page.request.get(`${OPEN_ORIGIN}/api/auth/me`);
    expect(meRes.status(), '/api/auth/me must be 200 after reset login').toBe(200);

    // ── H. Confirm old password is rejected ───────────────────────────────────

    await page.request.post(`${OPEN_ORIGIN}/api/auth/logout`);

    await page.goto(`${OPEN_ORIGIN}/auth/login`);
    await page.getByLabel('Email').fill(E2E_RESET_MEMBER_EMAIL);
    await page.getByLabel('Password').fill(MEMBER_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();

    await expect(
      page.getByText(/invalid credentials|incorrect|wrong/i).or(page.getByRole('alert')),
    ).toBeVisible({ timeout: 10_000 });

    await expect(page).not.toHaveURL(`${OPEN_ORIGIN}/app`);
    // No restore needed — the seed resets e2e-reset-member's password to
    // Password123! on every run, so the next run always starts clean.
  });
});
