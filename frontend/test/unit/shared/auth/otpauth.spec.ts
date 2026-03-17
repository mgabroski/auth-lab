import { describe, expect, it } from 'vitest';

import { parseOtpAuthUri } from '../../../../src/shared/auth/otpauth';

describe('parseOtpAuthUri', () => {
  it('extracts issuer, account label, and secret from a valid TOTP URI', () => {
    const parsed = parseOtpAuthUri(
      'otpauth://totp/Hubins:admin@example.com?secret=ABCDEF123456&issuer=Hubins',
    );

    expect(parsed).toEqual({
      issuer: 'Hubins',
      accountLabel: 'admin@example.com',
      secret: 'ABCDEF123456',
    });
  });

  it('returns null for invalid or unsupported URIs', () => {
    expect(parseOtpAuthUri('')).toBeNull();
    expect(parseOtpAuthUri('https://example.com/not-an-otpauth-uri')).toBeNull();
    expect(
      parseOtpAuthUri('otpauth://hotp/Hubins:admin@example.com?secret=ABCDEF123456'),
    ).toBeNull();
  });
});
