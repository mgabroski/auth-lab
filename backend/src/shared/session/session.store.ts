/**
 * backend/src/shared/session/session.store.ts
 *
 * WHY:
 * - Server-side session management via Redis (through Cache interface).
 * - Avoids JWT revocation complexity; sessions are instantly revocable via del().
 * - TTL enforced at Redis level (no expired session can be read).
 *
 * RULES:
 * - Depends only on Cache interface (DIP). Works with Redis in prod, InMemCache in tests.
 * - No HTTP concerns here (cookie handling lives in middleware).
 * - No business rules.
 */

import { randomUUID } from 'node:crypto';
import type { Cache } from '../cache/cache';
import type { SessionData } from './session.types';
import { SESSION_KEY_PREFIX } from './session.types';

export class SessionStore {
  constructor(
    private readonly cache: Cache,
    private readonly ttlSeconds: number,
  ) {}

  private key(sessionId: string): string {
    return `${SESSION_KEY_PREFIX}:${sessionId}`;
  }

  /**
   * Creates a new session and returns the session ID.
   * The caller is responsible for setting the cookie.
   */
  async create(data: SessionData): Promise<string> {
    const sessionId = randomUUID();

    await this.cache.set(this.key(sessionId), JSON.stringify(data), {
      ttlSeconds: this.ttlSeconds,
    });

    return sessionId;
  }

  /**
   * Loads session data by ID. Returns null if expired or not found.
   */
  async get(sessionId: string): Promise<SessionData | null> {
    const raw = await this.cache.get(this.key(sessionId));
    if (!raw) return null;

    try {
      return JSON.parse(raw) as SessionData;
    } catch {
      // Corrupted session — treat as missing
      await this.destroy(sessionId);
      return null;
    }
  }

  /**
   * Destroys a session (logout, forced revocation).
   */
  async destroy(sessionId: string): Promise<void> {
    await this.cache.del(this.key(sessionId));
  }
}
