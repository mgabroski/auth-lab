/**
 * backend/src/shared/security/rate-limit.ts
 *
 * WHY:
 * - Enforces security policies:
 *   - login attempts: 5 / 15min
 *   - forgot password: 3 / hour (silent)
 *   - MFA attempts: 5 / 15min
 *   - admin invite create/resend: locked per Brick 12
 * - Uses Redis in prod, but depends only on Cache (DIP).
 *
 * HOW TO USE:
 * - const limiter = new RateLimiter(cache, { prefix: "rl" })
 * - await limiter.hitOrThrow({ key: "login:ip:<hashed-ip>", limit: 5, windowSeconds: 900 })
 * - const allowed = await limiter.hitOrSkip({ key: "forgot:email:...", limit: 3, windowSeconds: 3600 })
 *
 * PII SAFETY:
 * - Never embed raw identifiers (email, IP) into cache keys.
 * - Always hash identifiers first (eg. tokenHasher.hash(email/ip)).
 *
 * TWO MODES:
 * - hitOrThrow: increments counter → throws AppError.rateLimited() if over limit.
 *   Used for login, register, reset-password, admin-invite — flows where 429 is the right response.
 * - hitOrSkip: increments counter → returns false if over limit (no throw).
 *   Used for forgot-password — the response must always be 200 to prevent email enumeration.
 *   The service checks the return value and silently skips sending the email when false is returned.
 *
 * ATOMICITY:
 * - Both methods use INCR-then-check, not check-then-INCR.
 * - INCR is atomic in Redis. Two concurrent requests both increment; the one
 *   that pushes over the limit gets back a value > limit and is rejected.
 *   There is no TOCTOU race.
 *
 * DISABLING:
 * - Pass `disabled: true` in opts to skip all checks (used in tests via di.ts).
 * - Never check NODE_ENV here — that decision belongs to the composition root.
 *
 * X6 — LOGIN_LOCKOUT_MESSAGE:
 * - Single source of truth for the locked error copy mandated by the provisioning spec.
 * - All login lockout callers import this constant and pass it as `message` to hitOrThrow().
 * - hitOrThrow() threads the message through to AppError.rateLimited() — no behavior
 *   change at call sites that do not supply a message (they still get "Rate limited").
 */

import type { Cache } from '../cache/cache';
import { AppError } from '../http/errors';

/**
 * Locked copy mandated by the Hubins provisioning spec.
 * Used at all login-lockout call sites (email + IP rate limit in execute-login-flow.ts).
 * Import this constant — do not inline the string.
 */
export const LOGIN_LOCKOUT_MESSAGE = 'Too many failed attempts. Try again in 15 minutes.';

export class RateLimiter {
  constructor(
    private readonly cache: Cache,
    private readonly opts?: { prefix?: string; disabled?: boolean },
  ) {}

  private buildKey(key: string): string {
    return this.opts?.prefix ? `${this.opts.prefix}:${key}` : key;
  }

  /**
   * Increments the counter for `key`.
   * Throws AppError.rateLimited() if the counter exceeds `limit`.
   *
   * Use for: login, register, reset-password, admin-invite — flows where 429 is
   * the correct HTTP response. The error-handler maps AppError → HTTP response
   * using the standard AppError path (no special-casing needed).
   *
   * X6: Accepts an optional `message` field. When supplied, the thrown
   * AppError.rateLimited() carries that message instead of the default
   * "Rate limited". Use LOGIN_LOCKOUT_MESSAGE at login call sites.
   */
  async hitOrThrow(input: {
    key: string;
    limit: number;
    windowSeconds: number;
    message?: string;
  }): Promise<void> {
    if (this.opts?.disabled) return;

    const fullKey = this.buildKey(input.key);
    const current = await this.cache.incr(fullKey, { ttlSeconds: input.windowSeconds });

    if (current > input.limit) {
      throw AppError.rateLimited({ key: fullKey, limit: input.limit }, input.message);
    }
  }

  /**
   * Increments the counter for `key`.
   * Returns `false` (without throwing) if the counter exceeds `limit`.
   * Returns `true` if the request is within the limit.
   *
   * Use for: forgot-password — the response must always be 200 (no 429) to
   * prevent an attacker from using rate limit errors as a signal that an email
   * address exists. The service checks the return value and silently skips
   * sending the email when `false` is returned.
   */
  async hitOrSkip(input: { key: string; limit: number; windowSeconds: number }): Promise<boolean> {
    if (this.opts?.disabled) return true;

    const fullKey = this.buildKey(input.key);
    const current = await this.cache.incr(fullKey, { ttlSeconds: input.windowSeconds });

    return current <= input.limit;
  }
}
