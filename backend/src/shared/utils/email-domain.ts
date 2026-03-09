/**
 * src/shared/utils/email-domain.ts
 *
 * WHY:
 * - Pure utility used by both auth flows (PII-minimized logging) and the
 *   tenants domain-allow-listing policy.
 * - Lives in shared/ because it belongs to neither module.
 *
 * RULES:
 * - Pure function. Never throws. No imports from modules/.
 */

export function emailDomain(email: string): string {
  const at = email.lastIndexOf('@');
  return at >= 0 ? email.slice(at + 1) : '';
}
