import { describe, expect, it } from 'vitest';

import type { AuthNextAction } from '../../../../src/shared/auth/contracts';
import {
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

function makeConfig() {
  return {
    tenant: {
      name: 'Acme',
      isActive: true,
      publicSignupEnabled: true,
      signupAllowed: true,
      allowedSso: [] as ('google' | 'microsoft')[],
    },
  };
}

function makeMe() {
  return {
    user: { id: 'u1', email: 'user@example.com', name: 'User' },
    membership: { id: 'm1', role: 'MEMBER' as const },
    tenant: { id: 't1', key: 'acme', name: 'Acme' },
    session: { mfaVerified: false, emailVerified: true },
    nextAction: 'NONE' as AuthNextAction,
  };
}

// ─── getPathForNextAction ─────────────────────────────────────────────────────

describe('getPathForNextAction', () => {
  it('NONE → /app', () => {
    expect(getPathForNextAction('NONE')).toBe(AUTHENTICATED_MEMBER_ENTRY_PATH);
  });

  it('EMAIL_VERIFICATION_REQUIRED → /verify-email', () => {
    expect(getPathForNextAction('EMAIL_VERIFICATION_REQUIRED')).toBe(AUTH_EMAIL_VERIFICATION_PATH);
  });

  it('MFA_SETUP_REQUIRED → /auth/mfa/setup', () => {
    expect(getPathForNextAction('MFA_SETUP_REQUIRED')).toBe(AUTH_MFA_SETUP_PATH);
  });

  it('MFA_REQUIRED → /auth/mfa/verify', () => {
    expect(getPathForNextAction('MFA_REQUIRED')).toBe(AUTH_MFA_VERIFY_PATH);
  });

  it('throws on unknown nextAction', () => {
    expect(() => getPathForNextAction('UNKNOWN' as AuthNextAction)).toThrow();
  });
});

// ─── getPostAuthRedirectPath ──────────────────────────────────────────────────

describe('getPostAuthRedirectPath', () => {
  it('NONE with no returnTo → /app', () => {
    expect(getPostAuthRedirectPath('NONE')).toBe(AUTHENTICATED_MEMBER_ENTRY_PATH);
  });

  it('NONE with a safe returnTo → uses returnTo', () => {
    expect(getPostAuthRedirectPath('NONE', '/admin/invites')).toBe('/admin/invites');
  });

  it('NONE with null returnTo → /app', () => {
    expect(getPostAuthRedirectPath('NONE', null)).toBe(AUTHENTICATED_MEMBER_ENTRY_PATH);
  });

  it('NONE with unsafe returnTo (external URL) → /app', () => {
    expect(getPostAuthRedirectPath('NONE', 'https://evil.com')).toBe(
      AUTHENTICATED_MEMBER_ENTRY_PATH,
    );
  });

  it('NONE with unsafe returnTo (protocol-relative) → /app', () => {
    expect(getPostAuthRedirectPath('NONE', '//evil.com')).toBe(AUTHENTICATED_MEMBER_ENTRY_PATH);
  });

  it('MFA_REQUIRED with returnTo matching continuation path → uses returnTo', () => {
    expect(getPostAuthRedirectPath('MFA_REQUIRED', AUTH_MFA_VERIFY_PATH)).toBe(
      AUTH_MFA_VERIFY_PATH,
    );
  });

  it('MFA_REQUIRED with unrelated safe returnTo → /auth/mfa/verify (continuation wins)', () => {
    expect(getPostAuthRedirectPath('MFA_REQUIRED', '/app')).toBe(AUTH_MFA_VERIFY_PATH);
  });

  it('MFA_SETUP_REQUIRED with no returnTo → /auth/mfa/setup', () => {
    expect(getPostAuthRedirectPath('MFA_SETUP_REQUIRED')).toBe(AUTH_MFA_SETUP_PATH);
  });

  it('EMAIL_VERIFICATION_REQUIRED with no returnTo → /verify-email', () => {
    expect(getPostAuthRedirectPath('EMAIL_VERIFICATION_REQUIRED')).toBe(
      AUTH_EMAIL_VERIFICATION_PATH,
    );
  });
});

// ─── getRouteStateRedirectPath ────────────────────────────────────────────────

describe('getRouteStateRedirectPath', () => {
  it('TENANT_UNAVAILABLE → /auth/unavailable', () => {
    const state: AuthRouteState = { kind: 'TENANT_UNAVAILABLE', config: makeConfig(), me: null };
    expect(getRouteStateRedirectPath(state)).toBe(AUTH_TENANT_UNAVAILABLE_PATH);
  });

  it('PUBLIC_ENTRY → /auth/login', () => {
    const state: AuthRouteState = { kind: 'PUBLIC_ENTRY', config: makeConfig(), me: null };
    expect(getRouteStateRedirectPath(state)).toBe(AUTH_PUBLIC_ENTRY_PATH);
  });

  it('EMAIL_VERIFICATION_REQUIRED → /verify-email', () => {
    const state: AuthRouteState = {
      kind: 'EMAIL_VERIFICATION_REQUIRED',
      config: makeConfig(),
      me: makeMe(),
    };
    expect(getRouteStateRedirectPath(state)).toBe(AUTH_EMAIL_VERIFICATION_PATH);
  });

  it('MFA_SETUP_REQUIRED → /auth/mfa/setup', () => {
    const state: AuthRouteState = {
      kind: 'MFA_SETUP_REQUIRED',
      config: makeConfig(),
      me: makeMe(),
    };
    expect(getRouteStateRedirectPath(state)).toBe(AUTH_MFA_SETUP_PATH);
  });

  it('MFA_REQUIRED → /auth/mfa/verify', () => {
    const state: AuthRouteState = {
      kind: 'MFA_REQUIRED',
      config: makeConfig(),
      me: makeMe(),
    };
    expect(getRouteStateRedirectPath(state)).toBe(AUTH_MFA_VERIFY_PATH);
  });

  it('AUTHENTICATED_MEMBER → /app', () => {
    const state: AuthRouteState = {
      kind: 'AUTHENTICATED_MEMBER',
      config: makeConfig(),
      me: makeMe(),
    };
    expect(getRouteStateRedirectPath(state)).toBe(AUTHENTICATED_MEMBER_ENTRY_PATH);
  });

  it('AUTHENTICATED_ADMIN → /admin', () => {
    const state: AuthRouteState = {
      kind: 'AUTHENTICATED_ADMIN',
      config: makeConfig(),
      me: { ...makeMe(), membership: { id: 'm1', role: 'ADMIN' } },
    };
    expect(getRouteStateRedirectPath(state)).toBe(AUTHENTICATED_ADMIN_ENTRY_PATH);
  });
});
