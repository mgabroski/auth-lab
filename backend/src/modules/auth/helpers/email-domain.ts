/**
 * backend/src/modules/auth/helpers/email-domain.ts
 *
 * WHY:
 * - emailDomain() is used for PII-minimized logging in multiple auth flows.
 * - Keeping it in one place prevents drift and avoids repeated tiny helpers.
 *
 * RULES:
 * - Pure function.
 * - Never throws.
 */

export function emailDomain(email: string): string {
  const at = email.lastIndexOf('@');
  return at >= 0 ? email.slice(at + 1) : '';
}
