/**
 * frontend/src/shared/auth/otpauth.ts
 *
 * WHY:
 * - Parses backend-provided `otpauth://` URIs into UI-friendly MFA enrollment
 *   details without re-implementing any backend auth logic.
 * - Lets the setup page show the exact issuer/account presentation a user
 *   should expect to see inside their authenticator app.
 *
 * RULES:
 * - Treat malformed or unsupported URIs as non-fatal UI fallback cases.
 * - Never mutate the backend-provided URI. It remains the source of truth.
 */

export type ParsedOtpAuthUri = {
  issuer: string | null;
  accountLabel: string | null;
  secret: string | null;
};

export function parseOtpAuthUri(uri: string): ParsedOtpAuthUri | null {
  try {
    const parsed = new URL(uri);

    if (parsed.protocol !== 'otpauth:' || parsed.hostname !== 'totp') {
      return null;
    }

    const rawLabel = decodeURIComponent(parsed.pathname.replace(/^\//, '')).trim();
    const labelParts = rawLabel.split(':');
    const issuerFromLabel = labelParts.length > 1 ? (labelParts[0]?.trim() ?? null) : null;
    const accountLabelFromPath =
      labelParts.length > 1 ? labelParts.slice(1).join(':').trim() : rawLabel || null;
    const issuerFromQuery = parsed.searchParams.get('issuer')?.trim() ?? null;

    return {
      issuer: issuerFromQuery || issuerFromLabel || null,
      accountLabel: accountLabelFromPath || null,
      secret: parsed.searchParams.get('secret')?.trim() ?? null,
    };
  } catch {
    return null;
  }
}
