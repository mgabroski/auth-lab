import { describe, expect, it } from 'vitest';

import type { ConfigResponse, MeResponse } from '../../../../src/shared/auth/contracts';
import { resolveAuthRouteState } from '../../../../src/shared/auth/route-state';

function makeConfig(overrides: Partial<ConfigResponse['tenant']> = {}): ConfigResponse {
  return {
    tenant: {
      name: 'Acme',
      isActive: true,
      publicSignupEnabled: true,
      allowedSso: ['google'],
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
        allowedSso: [],
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
});
