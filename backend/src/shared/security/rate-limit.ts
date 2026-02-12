/**
 * backend/src/shared/security/rate-limit.ts
 *
 * WHY:
 * - Enforces security policies:
 *   - login attempts: 5 / 15min
 *   - forgot password: 3 / hour (silent)
 *   - MFA attempts: 5 / 15min
 * - Uses Redis in prod, but depends only on Cache (DIP).
 *
 * HOW TO USE:
 * - const limiter = new RateLimiter(cache, { prefix: "rl" })
 * - await limiter.hitOrThrow({ key: "login:ip:1.2.3.4", limit: 5, windowSeconds: 900 })
 *
 * DISABLING:
 * - Pass `disabled: true` in opts to skip all checks (used in tests via di.ts).
 * - Never check NODE_ENV here — that decision belongs to the composition root.
 */

import type { Cache } from '../cache/cache';

export class RateLimitError extends Error {
  constructor(
    public readonly key: string,
    public readonly limit: number,
    public readonly windowSeconds: number,
  ) {
    super('Rate limit exceeded');
  }
}

export class RateLimiter {
  constructor(
    private readonly cache: Cache,
    private readonly opts?: { prefix?: string; disabled?: boolean },
  ) {}

  async hitOrThrow(input: { key: string; limit: number; windowSeconds: number }): Promise<void> {
    if (this.opts?.disabled) {
      return;
    }

    const fullKey = this.opts?.prefix ? `${this.opts.prefix}:${input.key}` : input.key;
    const current = await this.cache.incr(fullKey, { ttlSeconds: input.windowSeconds });

    if (current > input.limit) {
      throw new RateLimitError(fullKey, input.limit, input.windowSeconds);
    }
  }
}
