/**
 * frontend/test/unit/shared/auth/url-tokens.spec.ts
 *
 * WHY:
 * - Verifies the URL/token parsing utilities used across all auth pages.
 * - isSafeReturnToPath is a security boundary: open-redirect vectors must be
 *   explicitly covered. Any path allowed here can be used in a browser redirect.
 *
 * SECURITY COVERAGE NOTE (Phase 10):
 * - The standard cases (absolute URL, protocol-relative) were already present.
 * - Phase 10 adds explicit coverage for additional open-redirect attack vectors:
 *   backslash-prefix (\evil.com), data URI, and leading-whitespace.
 *   These are real browser-level vectors that isSafeReturnToPath must reject.
 */

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

  it('accepts a deeply nested path', () => {
    expect(isSafeReturnToPath('/admin/invites/123')).toBe(true);
  });

  it('rejects an absolute URL with https scheme', () => {
    expect(isSafeReturnToPath('https://evil.com/steal')).toBe(false);
  });

  it('rejects an absolute URL with http scheme', () => {
    expect(isSafeReturnToPath('http://evil.com/steal')).toBe(false);
  });

  it('rejects a protocol-relative URL (open redirect via //)', () => {
    expect(isSafeReturnToPath('//evil.com')).toBe(false);
  });

  it('rejects a backslash-prefixed path (open-redirect vector on some browsers)', () => {
    // Some browsers normalize \evil.com to //evil.com in navigation contexts.
    // The value does not start with '/' so it is already rejected by the first check.
    // This test makes the rejection of this specific vector explicit.
    expect(isSafeReturnToPath('\\evil.com')).toBe(false);
  });

  it('rejects a data URI (open-redirect and XSS vector)', () => {
    // data: URIs can execute script in some browser contexts.
    // They do not start with '/' so they are rejected by the first check.
    expect(isSafeReturnToPath('data:text/html,<script>alert(1)</script>')).toBe(false);
  });

  it('rejects a path with leading whitespace (isSafeReturnToPath does not trim)', () => {
    // A space-prefixed value is not a safe path. isSafeReturnToPath does not
    // trim whitespace — trimming happens at the readQueryParam layer.
    // A value with a leading space does not start with '/' so it is rejected.
    expect(isSafeReturnToPath(' /app')).toBe(false);
  });

  it('rejects a javascript: URI (XSS vector)', () => {
    expect(isSafeReturnToPath('javascript:alert(1)')).toBe(false);
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

  it('returns null for an unsafe returnTo (absolute URL)', () => {
    expect(getReturnToPath('returnTo=https%3A%2F%2Fevil.com')).toBeNull();
  });

  it('returns null when returnTo is absent', () => {
    expect(getReturnToPath('')).toBeNull();
  });

  it('returns null for a protocol-relative returnTo', () => {
    expect(getReturnToPath('returnTo=%2F%2Fevil.com')).toBeNull();
  });
});

// ─── normalizeReturnToPath ────────────────────────────────────────────────────

describe('normalizeReturnToPath', () => {
  it('returns the path when it is safe', () => {
    expect(normalizeReturnToPath('/dashboard')).toBe('/dashboard');
  });

  it('returns the fallback for an unsafe value (protocol-relative)', () => {
    expect(normalizeReturnToPath('//evil.com')).toBe('/');
  });

  it('returns a custom fallback', () => {
    expect(normalizeReturnToPath(null, '/auth/login')).toBe('/auth/login');
  });

  it('returns / when value is null and no fallback given', () => {
    expect(normalizeReturnToPath(null)).toBe('/');
  });

  it('returns the fallback for a backslash-prefixed value', () => {
    expect(normalizeReturnToPath('\\evil.com', '/auth/login')).toBe('/auth/login');
  });

  it('returns the fallback for a data URI', () => {
    expect(normalizeReturnToPath('data:text/html,xss', '/auth/login')).toBe('/auth/login');
  });
});
