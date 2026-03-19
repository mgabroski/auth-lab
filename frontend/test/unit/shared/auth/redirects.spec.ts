import { describe, expect, it } from 'vitest';

import type { AuthNextAction, MembershipRole } from '../../../../src/shared/auth/contracts';
import {
  ADMIN_SETTINGS_PATH,
  AUTH_EMAIL_VERIFICATION_PATH,
  AUTH_MFA_SETUP_PATH,
  AUTH_MFA_VERIFY_PATH,
  AUTH_PUBLIC_ENTRY_PATH,
  AUTH_TENANT_UNAVAILABLE_PATH,
  AUTHENTICATED_ADMIN_ENTRY_PATH,
  AUTHENTICATED_MEMBER_ENTRY_PATH,
  getPathForNextAction,
  getPostAuthRedirectPath,
  getRouteStateRedirectPath,
} from '../../../../src/shared/auth/redirects';
import type { AuthRouteState } from '../../../../src/shared/auth/route-state';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeConfig(setupCompleted = true) {
  return {
    tenant: {
      name: 'Acme',
      isActive: true,
      publicSignupEnabled: true,
      signupAllowed: true,
      allowedSso: [] as ('google' | 'microsoft')[],
      setupCompleted,
    },
  };
}

function makeMe(role: MembershipRole = 'MEMBER', nextAction: AuthNextAction = 'NONE') {
  return {
    user: { id: 'u1', email: 'user@example.com', name: 'User' },
    membership: { id: 'm1', role },
    tenant: { id: 't1', key: 'acme', name: 'Acme' },
    session: { mfaVerified: false, emailVerified: true },
    nextAction,
  };
}

// ─── getPathForNextAction ─────────────────────────────────────────────────────

describe('getPathForNextAction', () => {
  // NONE is role-aware (Phase 9 fix)
  it('NONE + MEMBER → /app', () => {
    expect(getPathForNextAction('NONE', 'MEMBER')).toBe(AUTHENTICATED_MEMBER_ENTRY_PATH);
  });

  it('NONE + ADMIN → /admin', () => {
    expect(getPathForNextAction('NONE', 'ADMIN')).toBe(AUTHENTICATED_ADMIN_ENTRY_PATH);
  });

  it('EMAIL_VERIFICATION_REQUIRED → /verify-email (role-independent)', () => {
    expect(getPathForNextAction('EMAIL_VERIFICATION_REQUIRED', 'MEMBER')).toBe(
      AUTH_EMAIL_VERIFICATION_PATH,
    );
    expect(getPathForNextAction('EMAIL_VERIFICATION_REQUIRED', 'ADMIN')).toBe(
      AUTH_EMAIL_VERIFICATION_PATH,
    );
  });

  it('MFA_SETUP_REQUIRED → /auth/mfa/setup (role-independent)', () => {
    expect(getPathForNextAction('MFA_SETUP_REQUIRED', 'ADMIN')).toBe(AUTH_MFA_SETUP_PATH);
    expect(getPathForNextAction('MFA_SETUP_REQUIRED', 'MEMBER')).toBe(AUTH_MFA_SETUP_PATH);
  });

  it('MFA_REQUIRED → /auth/mfa/verify (role-independent)', () => {
    expect(getPathForNextAction('MFA_REQUIRED', 'ADMIN')).toBe(AUTH_MFA_VERIFY_PATH);
    expect(getPathForNextAction('MFA_REQUIRED', 'MEMBER')).toBe(AUTH_MFA_VERIFY_PATH);
  });

  it('throws on unknown nextAction', () => {
    expect(() => getPathForNextAction('UNKNOWN' as AuthNextAction, 'MEMBER')).toThrow();
  });
});

// ─── getPostAuthRedirectPath ──────────────────────────────────────────────────

describe('getPostAuthRedirectPath', () => {
  it('NONE + MEMBER with no returnTo → /app', () => {
    expect(getPostAuthRedirectPath('NONE', 'MEMBER')).toBe(AUTHENTICATED_MEMBER_ENTRY_PATH);
  });

  it('NONE + ADMIN with no returnTo → /admin', () => {
    expect(getPostAuthRedirectPath('NONE', 'ADMIN')).toBe(AUTHENTICATED_ADMIN_ENTRY_PATH);
  });

  it('NONE + MEMBER with a safe returnTo → uses returnTo', () => {
    expect(getPostAuthRedirectPath('NONE', 'MEMBER', '/dashboard')).toBe('/dashboard');
  });

  it('NONE + ADMIN with a safe returnTo → uses returnTo', () => {
    expect(getPostAuthRedirectPath('NONE', 'ADMIN', '/admin/invites')).toBe('/admin/invites');
  });

  it('NONE + MEMBER with null returnTo → /app', () => {
    expect(getPostAuthRedirectPath('NONE', 'MEMBER', null)).toBe(AUTHENTICATED_MEMBER_ENTRY_PATH);
  });

  it('NONE + MEMBER with unsafe returnTo (external URL) → /app', () => {
    expect(getPostAuthRedirectPath('NONE', 'MEMBER', 'https://evil.com')).toBe(
      AUTHENTICATED_MEMBER_ENTRY_PATH,
    );
  });

  it('NONE + MEMBER with unsafe returnTo (protocol-relative) → /app', () => {
    expect(getPostAuthRedirectPath('NONE', 'MEMBER', '//evil.com')).toBe(
      AUTHENTICATED_MEMBER_ENTRY_PATH,
    );
  });

  it('MFA_REQUIRED + ADMIN with returnTo matching continuation path → uses returnTo', () => {
    expect(getPostAuthRedirectPath('MFA_REQUIRED', 'ADMIN', AUTH_MFA_VERIFY_PATH)).toBe(
      AUTH_MFA_VERIFY_PATH,
    );
  });

  it('MFA_REQUIRED + ADMIN with unrelated safe returnTo → /auth/mfa/verify (continuation wins)', () => {
    expect(getPostAuthRedirectPath('MFA_REQUIRED', 'ADMIN', '/app')).toBe(AUTH_MFA_VERIFY_PATH);
  });

  it('MFA_SETUP_REQUIRED + ADMIN with no returnTo → /auth/mfa/setup', () => {
    expect(getPostAuthRedirectPath('MFA_SETUP_REQUIRED', 'ADMIN')).toBe(AUTH_MFA_SETUP_PATH);
  });

  it('EMAIL_VERIFICATION_REQUIRED + MEMBER with no returnTo → /verify-email', () => {
    expect(getPostAuthRedirectPath('EMAIL_VERIFICATION_REQUIRED', 'MEMBER')).toBe(
      AUTH_EMAIL_VERIFICATION_PATH,
    );
  });
});

// ─── getRouteStateRedirectPath ────────────────────────────────────────────────

describe('getRouteStateRedirectPath', () => {
  it('TENANT_UNAVAILABLE → /auth/unavailable', () => {
    const state: AuthRouteState = {
      kind: 'TENANT_UNAVAILABLE',
      config: makeConfig(),
      me: null,
    };
    expect(getRouteStateRedirectPath(state)).toBe(AUTH_TENANT_UNAVAILABLE_PATH);
  });

  it('PUBLIC_ENTRY → /auth/login', () => {
    const state: AuthRouteState = {
      kind: 'PUBLIC_ENTRY',
      config: makeConfig(),
      me: null,
    };
    expect(getRouteStateRedirectPath(state)).toBe(AUTH_PUBLIC_ENTRY_PATH);
  });

  it('EMAIL_VERIFICATION_REQUIRED → /verify-email', () => {
    const state: AuthRouteState = {
      kind: 'EMAIL_VERIFICATION_REQUIRED',
      config: makeConfig(),
      me: makeMe('MEMBER', 'EMAIL_VERIFICATION_REQUIRED'),
    };
    expect(getRouteStateRedirectPath(state)).toBe(AUTH_EMAIL_VERIFICATION_PATH);
  });

  it('MFA_SETUP_REQUIRED → /auth/mfa/setup', () => {
    const state: AuthRouteState = {
      kind: 'MFA_SETUP_REQUIRED',
      config: makeConfig(),
      me: makeMe('ADMIN', 'MFA_SETUP_REQUIRED'),
    };
    expect(getRouteStateRedirectPath(state)).toBe(AUTH_MFA_SETUP_PATH);
  });

  it('MFA_REQUIRED → /auth/mfa/verify', () => {
    const state: AuthRouteState = {
      kind: 'MFA_REQUIRED',
      config: makeConfig(),
      me: makeMe('ADMIN', 'MFA_REQUIRED'),
    };
    expect(getRouteStateRedirectPath(state)).toBe(AUTH_MFA_VERIFY_PATH);
  });

  it('AUTHENTICATED_MEMBER → /app', () => {
    const state: AuthRouteState = {
      kind: 'AUTHENTICATED_MEMBER',
      config: makeConfig(),
      me: makeMe('MEMBER', 'NONE'),
    };
    expect(getRouteStateRedirectPath(state)).toBe(AUTHENTICATED_MEMBER_ENTRY_PATH);
  });

  it('AUTHENTICATED_ADMIN → /admin', () => {
    const state: AuthRouteState = {
      kind: 'AUTHENTICATED_ADMIN',
      config: makeConfig(),
      me: makeMe('ADMIN', 'NONE'),
    };
    expect(getRouteStateRedirectPath(state)).toBe(AUTHENTICATED_ADMIN_ENTRY_PATH);
  });

  it('ADMIN_SETTINGS_PATH constant resolves to /admin/settings', () => {
    expect(ADMIN_SETTINGS_PATH).toBe('/admin/settings');
  });
});
