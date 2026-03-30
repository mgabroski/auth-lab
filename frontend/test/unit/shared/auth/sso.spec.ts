import { afterEach, describe, expect, it, vi } from 'vitest';

import { buildSsoStartPath, startSso } from '../../../../src/shared/auth/sso';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('buildSsoStartPath', () => {
  it('builds a same-origin Google SSO start path with no returnTo by default', () => {
    expect(buildSsoStartPath('google')).toBe('/api/auth/sso/google');
  });

  it('builds a same-origin Microsoft SSO start path with a safe returnTo', () => {
    expect(buildSsoStartPath('microsoft', { returnTo: '/admin/invites' })).toBe(
      '/api/auth/sso/microsoft?returnTo=%2Fadmin%2Finvites',
    );
  });

  it('drops an unsafe external returnTo', () => {
    expect(buildSsoStartPath('google', { returnTo: 'https://evil.example.com' })).toBe(
      '/api/auth/sso/google',
    );
  });

  it('drops a protocol-relative returnTo', () => {
    expect(buildSsoStartPath('google', { returnTo: '//evil.example.com' })).toBe(
      '/api/auth/sso/google',
    );
  });

  it('drops a backslash redirect vector returnTo', () => {
    expect(buildSsoStartPath('google', { returnTo: '/\\evil.example.com' })).toBe(
      '/api/auth/sso/google',
    );
  });
});

describe('startSso', () => {
  it('starts SSO with full browser navigation using the same-origin /api path', () => {
    const assignMock = vi.fn();

    vi.stubGlobal('window', {
      location: {
        assign: assignMock,
      },
    });

    startSso('google', { returnTo: '/app' });

    expect(assignMock).toHaveBeenCalledTimes(1);
    expect(assignMock).toHaveBeenCalledWith('/api/auth/sso/google?returnTo=%2Fapp');
  });

  it('throws when called outside the browser', () => {
    expect(() => startSso('microsoft')).toThrow('startSso() can only run in the browser.');
  });
});
