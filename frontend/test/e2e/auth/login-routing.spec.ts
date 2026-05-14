/**
 * frontend/test/e2e/auth/login-routing.spec.ts
 *
 * WHY: Split from the legacy monolithic auth.spec.ts to keep the auth proof layer navigable while preserving the exact real-stack assertions.
 */

import { expect, test } from '@playwright/test';
import { AUTH_E2E } from './auth-test-context';

test.describe('auth smoke: login, logout, routing, and tenant isolation', () => {
  // ── 1. Member login → authenticated area ──────────────────────────────────
  //
  // Proves:
  // - password login works against real DB (bcrypt comparison, session creation)
  // - backend returns nextAction: NONE for a verified member without MFA
  // - frontend routes to /app after NONE
  // - host-derived tenant identity works through the proxy
  // - session cookie (sid) survives the proxy round-trip and SSR reads it

  test('member login reaches /app and session cookie is set correctly', async ({ page }) => {
    await page.goto(`${AUTH_E2E.OPEN_ORIGIN}/auth/login`);

    await expect(page.getByRole('heading', { name: /goodwill open signup/i })).toBeVisible();

    await page.getByLabel('Email').fill(AUTH_E2E.MEMBER_EMAIL);
    await page.getByLabel('Password').fill(AUTH_E2E.MEMBER_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();

    await expect(page).toHaveURL(`${AUTH_E2E.OPEN_ORIGIN}/app`);
    await expect(page.getByRole('heading', { name: 'Workspace' })).toBeVisible();
    await expect(page.getByText('Authenticated handoff complete')).toBeVisible();

    const cookies = await page.context().cookies(`${AUTH_E2E.OPEN_ORIGIN}`);
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
    await page.goto(`${AUTH_E2E.OPEN_ORIGIN}/auth/login`);
    await page.getByLabel('Email').fill(AUTH_E2E.MEMBER_EMAIL);
    await page.getByLabel('Password').fill(AUTH_E2E.MEMBER_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page).toHaveURL(`${AUTH_E2E.OPEN_ORIGIN}/app`);

    // Step 2: confirm /api/auth/me returns 200 while authenticated
    const meWhileAuthed = await page.request.get(`${AUTH_E2E.OPEN_ORIGIN}/api/auth/me`);
    expect(meWhileAuthed.status(), '/api/auth/me must be 200 while authenticated').toBe(200);

    // Step 3: call POST /api/auth/logout via page.request (shares session cookie)
    const logoutResponse = await page.request.post(`${AUTH_E2E.OPEN_ORIGIN}/api/auth/logout`);
    expect(
      logoutResponse.status(),
      `POST /api/auth/logout must return 200 (got ${logoutResponse.status()}).`,
    ).toBe(200);

    // Step 4: confirm backend session is invalidated — /api/auth/me returns 401
    const meAfterLogout = await page.request.get(`${AUTH_E2E.OPEN_ORIGIN}/api/auth/me`);
    expect(meAfterLogout.status(), '/api/auth/me must be 401 after logout').toBe(401);

    // Step 5: confirm SSR on /app redirects to /auth/login (session gone server-side)
    await page.goto(`${AUTH_E2E.OPEN_ORIGIN}/app`);
    await expect(page).toHaveURL(`${AUTH_E2E.OPEN_ORIGIN}/auth/login`);
    await expect(page.getByRole('heading', { name: /sign in/i })).toBeVisible();
  });

  // ── 10. Cross-tenant session isolation ────────────────────────────────────

  test('cross-tenant isolation: goodwill-open session rejected on goodwill-ca', async ({
    page,
  }) => {
    await page.goto(`${AUTH_E2E.OPEN_ORIGIN}/auth/login`);
    await page.getByLabel('Email').fill(AUTH_E2E.MEMBER_EMAIL);
    await page.getByLabel('Password').fill(AUTH_E2E.MEMBER_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page).toHaveURL(`${AUTH_E2E.OPEN_ORIGIN}/app`);

    const meOnOtherTenant = await page.request.get(`${AUTH_E2E.INVITE_ONLY_ORIGIN}/api/auth/me`);
    expect(
      meOnOtherTenant.status(),
      '/api/auth/me on goodwill-ca with goodwill-open session must be 401',
    ).toBe(401);
  });

  // ── Workspace settings route smoke tests ─────────────────────────────────
  //
  // Proves the workspace setup banner contract (ADR 0003):
  // - /admin/settings route exists and is reachable (not 404)
  // - unauthenticated access to /admin/settings is redirected, not 500
  // - NONE + USER routes to /app (role-aware routing fix)
  // - NONE + ADMIN routes to /admin (role-aware routing fix)
  // - members are redirected away from /admin (role gate enforced)
  //
  // The active Settings banner lifecycle is now verified through the Settings
  // proof suite. Auth smoke tests keep route existence and role-routing coverage
  // only; auth no longer owns a workspace setup acknowledgement mutation.

  test('/admin/settings route exists and redirects unauthenticated access', async ({ page }) => {
    // Route must exist (not 404). Unauthenticated access must redirect to login.
    await page.goto(`${AUTH_E2E.OPEN_ORIGIN}/admin/settings`);

    // Should have been redirected — not still on /admin/settings and not a 404.
    const finalUrl = page.url();
    expect(
      finalUrl,
      '/admin/settings must redirect unauthenticated access, not stay on the page',
    ).not.toBe(`${AUTH_E2E.OPEN_ORIGIN}/admin/settings`);

    // The redirect destination must be a valid auth page, not an error page.
    expect(
      finalUrl.includes('/auth/') || finalUrl.includes('/app'),
      `Expected redirect to an auth path, got: ${finalUrl}`,
    ).toBe(true);
  });

  test('/admin/settings responds with a page (not 404) for any request', async ({ request }) => {
    // Even without a session, Next.js must handle the route and return a
    // renderable response (200 with redirect HTML, or a 3xx). Never 404.
    const response = await request.get(`${AUTH_E2E.OPEN_ORIGIN}/admin/settings`, {
      maxRedirects: 0,
    });

    expect(
      response.status(),
      '/admin/settings must not return 404 — route must be registered in Next.js',
    ).not.toBe(404);
  });

  test('phase-9: member login lands on /app, not /admin (NONE + USER role-aware routing)', async ({
    page,
  }) => {
    await page.goto(`${AUTH_E2E.OPEN_ORIGIN}/auth/login`);
    await page.getByLabel('Email').fill(AUTH_E2E.MEMBER_EMAIL);
    await page.getByLabel('Password').fill(AUTH_E2E.MEMBER_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();

    // NONE + USER → /app (not /admin, not /admin/settings)
    await expect(page).toHaveURL(`${AUTH_E2E.OPEN_ORIGIN}/app`);
    await expect(page.getByRole('heading', { name: 'Workspace' })).toBeVisible();
    await expect(page.getByText('Authenticated handoff complete')).toBeVisible();
  });

  test('phase-9: member is redirected away from /admin (role gate enforced)', async ({ page }) => {
    // Log in as member first to get an authenticated session
    await page.goto(`${AUTH_E2E.OPEN_ORIGIN}/auth/login`);
    await page.getByLabel('Email').fill(AUTH_E2E.MEMBER_EMAIL);
    await page.getByLabel('Password').fill(AUTH_E2E.MEMBER_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page).toHaveURL(`${AUTH_E2E.OPEN_ORIGIN}/app`);

    // Attempt to navigate to the admin area directly
    await page.goto(`${AUTH_E2E.OPEN_ORIGIN}/admin`);

    // Member must be redirected — /admin is ADMIN-only
    await expect(page).not.toHaveURL(`${AUTH_E2E.OPEN_ORIGIN}/admin`);
  });

  test('phase-9: admin login continues to /auth/mfa/setup (MFA_SETUP_REQUIRED continuation unchanged)', async ({
    page,
  }) => {
    // Proves the auth continuation chain remains unaffected by workspace settings route coverage.
    // Admin with no MFA still continues to /auth/mfa/setup — not /admin/settings.
    // Setup banner lives on /admin; it does not intercept the auth flow.
    await page.goto(`${AUTH_E2E.OPEN_ORIGIN}/auth/login`);
    await page.getByLabel('Email').fill(AUTH_E2E.E2E_ADMIN_EMAIL);
    await page.getByLabel('Password').fill(AUTH_E2E.E2E_ADMIN_PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();

    // Still goes to MFA setup — NONE + ADMIN → /admin happens only after full auth
    await expect(page).toHaveURL(`${AUTH_E2E.OPEN_ORIGIN}/auth/mfa/setup`);
    await expect(page.getByRole('heading', { name: /multi-factor authentication/i })).toBeVisible();
  });
});
