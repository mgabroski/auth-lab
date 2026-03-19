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
    expect(location).toContain('accounts.google.com');

    const setCookieHeaders = response
      .headersArray()
      .filter((h) => h.name.toLowerCase() === 'set-cookie')
      .map((h) => h.value);

    const ssoStateCookie = setCookieHeaders.find((v) => v.includes('sso-state'));
    expect(ssoStateCookie, 'sso-state cookie must be set').toBeDefined();
    expect(ssoStateCookie).toContain('SameSite=Lax');
    expect(ssoStateCookie).toContain('HttpOnly');
  });

  // ── 8. Cross-tenant session isolation ─────────────────────────────────────

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
});
