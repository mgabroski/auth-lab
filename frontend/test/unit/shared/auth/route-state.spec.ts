import { describe, expect, it } from 'vitest';

import type { ConfigResponse, MeResponse } from '../../../../src/shared/auth/contracts';
import { resolveAuthRouteState } from '../../../../src/shared/auth/route-state';

function makeConfig(overrides: Partial<ConfigResponse['tenant']> = {}): ConfigResponse {
  return {
    tenant: {
      name: 'Acme',
      isActive: true,
      publicSignupEnabled: true,
      signupAllowed: true,
      allowedSso: ['google'],
      // Phase 9: setupCompleted is a required field. Default to true in tests —
      // override explicitly when testing the banner-visible case.
      setupCompleted: true,
      ...overrides,
    },
  };
}

function makeMe(overrides: Partial<MeResponse> = {}): MeResponse {
  return {
    user: {
      id: 'user-1',
      email: 'user@example.com',
      name: 'Test User',
    },
    membership: {
      id: 'membership-1',
      role: 'MEMBER',
    },
    tenant: {
      id: 'tenant-1',
      key: 'acme',
      name: 'Acme',
    },
    session: {
      mfaVerified: false,
      emailVerified: true,
    },
    nextAction: 'NONE',
    ...overrides,
  };
}

describe('resolveAuthRouteState', () => {
  it('returns TENANT_UNAVAILABLE when /auth/config says the tenant is inactive', () => {
    const state = resolveAuthRouteState({
      config: makeConfig({
        isActive: false,
        publicSignupEnabled: false,
        signupAllowed: false,
        allowedSso: [],
        setupCompleted: false,
      }),
      me: null,
    });

    expect(state.kind).toBe('TENANT_UNAVAILABLE');
  });

  it('returns PUBLIC_ENTRY when the tenant is active and there is no session', () => {
    const state = resolveAuthRouteState({
      config: makeConfig(),
      me: null,
    });

    expect(state.kind).toBe('PUBLIC_ENTRY');
  });

  it('maps NONE + MEMBER to AUTHENTICATED_MEMBER', () => {
    const state = resolveAuthRouteState({
      config: makeConfig(),
      me: makeMe({
        nextAction: 'NONE',
        membership: { id: 'membership-1', role: 'MEMBER' },
      }),
    });

    expect(state.kind).toBe('AUTHENTICATED_MEMBER');
  });

  it('maps NONE + ADMIN to AUTHENTICATED_ADMIN', () => {
    const state = resolveAuthRouteState({
      config: makeConfig(),
      me: makeMe({
        nextAction: 'NONE',
        membership: { id: 'membership-1', role: 'ADMIN' },
      }),
    });

    expect(state.kind).toBe('AUTHENTICATED_ADMIN');
  });

  it('maps EMAIL_VERIFICATION_REQUIRED directly from backend nextAction', () => {
    const state = resolveAuthRouteState({
      config: makeConfig(),
      me: makeMe({ nextAction: 'EMAIL_VERIFICATION_REQUIRED' }),
    });

    expect(state.kind).toBe('EMAIL_VERIFICATION_REQUIRED');
  });

  it('maps MFA_SETUP_REQUIRED directly from backend nextAction', () => {
    const state = resolveAuthRouteState({
      config: makeConfig(),
      me: makeMe({ nextAction: 'MFA_SETUP_REQUIRED' }),
    });

    expect(state.kind).toBe('MFA_SETUP_REQUIRED');
  });

  it('maps MFA_REQUIRED directly from backend nextAction', () => {
    const state = resolveAuthRouteState({
      config: makeConfig(),
      me: makeMe({ nextAction: 'MFA_REQUIRED' }),
    });

    expect(state.kind).toBe('MFA_REQUIRED');
  });

  it('AUTHENTICATED_ADMIN carries setupCompleted=false through config for banner rendering', () => {
    // Phase 9: the route state passes config through so admin page can read
    // config.tenant.setupCompleted to conditionally render the setup banner.
    const state = resolveAuthRouteState({
      config: makeConfig({ setupCompleted: false }),
      me: makeMe({
        nextAction: 'NONE',
        membership: { id: 'membership-1', role: 'ADMIN' },
      }),
    });

    expect(state.kind).toBe('AUTHENTICATED_ADMIN');
    expect(state.config.tenant.setupCompleted).toBe(false);
  });

  it('AUTHENTICATED_ADMIN carries setupCompleted=true through config when setup is done', () => {
    const state = resolveAuthRouteState({
      config: makeConfig({ setupCompleted: true }),
      me: makeMe({
        nextAction: 'NONE',
        membership: { id: 'membership-1', role: 'ADMIN' },
      }),
    });

    expect(state.kind).toBe('AUTHENTICATED_ADMIN');
    expect(state.config.tenant.setupCompleted).toBe(true);
  });

  it('signupAllowed is false when adminInviteRequired overrides publicSignupEnabled', () => {
    // This test documents the specific scenario that motivated adding signupAllowed:
    // publicSignupEnabled=true but adminInviteRequired=true means signup is blocked.
    // The frontend must use signupAllowed, not publicSignupEnabled.
    const state = resolveAuthRouteState({
      config: makeConfig({
        publicSignupEnabled: true,
        signupAllowed: false, // adminInviteRequired is true on the backend
      }),
      me: null,
    });

    // Tenant is active, so the result is PUBLIC_ENTRY regardless of signupAllowed.
    // The signupAllowed flag controls whether the signup UI is rendered —
    // it does not change the route state category itself.
    expect(state.kind).toBe('PUBLIC_ENTRY');
    expect(state.config.tenant.signupAllowed).toBe(false);
    expect(state.config.tenant.publicSignupEnabled).toBe(true);
  });
});
