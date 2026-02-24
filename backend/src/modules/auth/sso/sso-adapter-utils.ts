/**
 * backend/src/modules/auth/sso/sso-adapter-utils.ts
 *
 * WHY:
 * - Shared tiny helpers for adapters to avoid duplication.
 * - Keeps adapters focused on provider-specific rules (SRP).
 */

export function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object';
}

export function getString(obj: Record<string, unknown>, key: string): string | undefined {
  const v = obj[key];
  return typeof v === 'string' && v.length ? v : undefined;
}
