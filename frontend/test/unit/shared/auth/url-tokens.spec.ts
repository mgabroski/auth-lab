import { describe, expect, it } from 'vitest';

import {
  getReturnToPath,
  getVerificationToken,
  isSafeReturnToPath,
  normalizeReturnToPath,
  readQueryParam,
  readTokenQueryParam,
} from '../../../../src/shared/auth/url-tokens';

// ─── isSafeReturnToPath ───────────────────────────────────────────────────────

describe('isSafeReturnToPath', () => {
  it('accepts a plain path', () => {
    expect(isSafeReturnToPath('/app')).toBe(true);
  });

  it('accepts a path with query string', () => {
    expect(isSafeReturnToPath('/auth/mfa/verify?from=login')).toBe(true);
  });

  it('accepts root /', () => {
    expect(isSafeReturnToPath('/')).toBe(true);
  });

  it('rejects an absolute URL', () => {
    expect(isSafeReturnToPath('https://evil.com/steal')).toBe(false);
  });

  it('rejects a protocol-relative URL (open redirect)', () => {
    expect(isSafeReturnToPath('//evil.com')).toBe(false);
  });

  it('rejects an empty string', () => {
    expect(isSafeReturnToPath('')).toBe(false);
  });

  it('rejects null', () => {
    expect(isSafeReturnToPath(null)).toBe(false);
  });

  it('rejects undefined', () => {
    expect(isSafeReturnToPath(undefined)).toBe(false);
  });
});

// ─── readQueryParam ───────────────────────────────────────────────────────────

describe('readQueryParam — string input', () => {
  it('reads a param from a query string', () => {
    expect(readQueryParam('token=abc123', 'token')).toBe('abc123');
  });

  it('reads a param from a ?-prefixed query string', () => {
    expect(readQueryParam('?token=abc123', 'token')).toBe('abc123');
  });

  it('returns null when param is absent', () => {
    expect(readQueryParam('other=value', 'token')).toBeNull();
  });

  it('returns null for a blank value', () => {
    expect(readQueryParam('token=   ', 'token')).toBeNull();
  });
});

describe('readQueryParam — URLSearchParams input', () => {
  it('reads a param', () => {
    expect(readQueryParam(new URLSearchParams('token=xyz'), 'token')).toBe('xyz');
  });

  it('returns null when absent', () => {
    expect(readQueryParam(new URLSearchParams(''), 'token')).toBeNull();
  });
});

describe('readQueryParam — URL input', () => {
  it('reads a param from a URL object', () => {
    expect(readQueryParam(new URL('http://example.com/?token=urlval'), 'token')).toBe('urlval');
  });
});

describe('readQueryParam — plain object (Next.js searchParams)', () => {
  it('reads a string value', () => {
    expect(readQueryParam({ token: 'from-object' }, 'token')).toBe('from-object');
  });

  it('reads the first value from an array', () => {
    expect(readQueryParam({ token: ['first', 'second'] }, 'token')).toBe('first');
  });

  it('returns null when key is absent', () => {
    expect(readQueryParam({}, 'token')).toBeNull();
  });

  it('returns null when value is undefined', () => {
    expect(readQueryParam({ token: undefined }, 'token')).toBeNull();
  });
});

// ─── readTokenQueryParam ──────────────────────────────────────────────────────

describe('readTokenQueryParam', () => {
  it('reads the token param', () => {
    expect(readTokenQueryParam('token=mytoken')).toBe('mytoken');
  });

  it('returns null when token is absent', () => {
    expect(readTokenQueryParam('other=value')).toBeNull();
  });
});

// ─── getVerificationToken ─────────────────────────────────────────────────────

describe('getVerificationToken', () => {
  it('reads a verification token from a query string', () => {
    expect(getVerificationToken('token=verify123')).toBe('verify123');
  });

  it('returns null when absent', () => {
    expect(getVerificationToken('')).toBeNull();
  });
});

// ─── getReturnToPath ──────────────────────────────────────────────────────────

describe('getReturnToPath', () => {
  it('returns a safe returnTo path', () => {
    expect(getReturnToPath('returnTo=%2Fadmin')).toBe('/admin');
  });

  it('returns null for an unsafe returnTo', () => {
    expect(getReturnToPath('returnTo=https%3A%2F%2Fevil.com')).toBeNull();
  });

  it('returns null when returnTo is absent', () => {
    expect(getReturnToPath('')).toBeNull();
  });
});

// ─── normalizeReturnToPath ────────────────────────────────────────────────────

describe('normalizeReturnToPath', () => {
  it('returns the path when it is safe', () => {
    expect(normalizeReturnToPath('/dashboard')).toBe('/dashboard');
  });

  it('returns the fallback for an unsafe value', () => {
    expect(normalizeReturnToPath('//evil.com')).toBe('/');
  });

  it('returns a custom fallback', () => {
    expect(normalizeReturnToPath(null, '/auth/login')).toBe('/auth/login');
  });

  it('returns / when value is null and no fallback given', () => {
    expect(normalizeReturnToPath(null)).toBe('/');
  });
});
