/**
 * src/shared/session/session.store.ts
 *
 * WHY:
 * - Server-side session management via Redis (through Cache interface).
 * - Avoids JWT revocation complexity; sessions are instantly revocable via del().
 * - TTL enforced at Redis level (no expired session can be read).
 *
 * USER-SESSION INDEX (destroyAllForUser):
 * - On create(): SADD session:user:{userId} {sessionId} with TTL refresh.
 *   This maintains a Redis SET of all active session IDs for the user.
 * - On destroy(): SREM removes the session ID from the user index, then DELs the session.
 * - On destroyAllForUser(): SMEMBERS reads all session IDs → DEL each → DEL the index.
 *
 * WHY REDIS SET, NOT JSON ARRAY:
 * - SADD is idempotent → no duplicates possible.
 * - SMEMBERS is one atomic read → no concurrent write conflicts.
 * - SREM removes one member atomically → parallel logouts don't corrupt state.
 * - TTL on the index key prevents unbounded growth (stale IDs expire naturally).
 *
 * RULES:
 * - Depends only on Cache interface (DIP). Works with Redis in prod, InMemCache in tests.
 * - No HTTP concerns here (cookie handling lives in middleware).
 * - No business rules.
 */

import { randomUUID } from 'node:crypto';
import type { Cache } from '../cache/cache';
import type { TokenHasher } from '../security/token-hasher';
import type { SessionData } from './session.types';
import { SESSION_KEY_PREFIX, SESSION_USER_INDEX_PREFIX } from './session.types';

export class SessionStore {
  constructor(
    private readonly cache: Cache,
    private readonly ttlSeconds: number,
    private readonly tokenHasher: TokenHasher,
  ) {}

  private key(sessionId: string): string {
    return `${SESSION_KEY_PREFIX}:${sessionId}`;
  }

  private userIndexKey(userId: string): string {
    // Stage 4: never place stable identifiers (UUIDs) directly in Redis keys.
    // Hash userId to reduce accidental PII leakage via key scans/metrics/logs.
    return `${SESSION_USER_INDEX_PREFIX}:${this.tokenHasher.hash(userId)}`;
  }

  /**
   * Creates a new session and returns the session ID.
   * Also registers the session ID in the per-user index (for destroyAllForUser).
   * The caller is responsible for setting the cookie.
   */
  async create(data: SessionData): Promise<string> {
    const sessionId = randomUUID();

    await this.cache.set(this.key(sessionId), JSON.stringify(data), {
      ttlSeconds: this.ttlSeconds,
    });

    // Register session in per-user index.
    // TTL on the index is refreshed to at least as long as the session TTL.
    await this.cache.sadd(this.userIndexKey(data.userId), sessionId, {
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
   * Destroys a single session (logout, forced revocation).
   * Also removes the session ID from the per-user index.
   */
  async destroy(sessionId: string): Promise<void> {
    const raw = await this.cache.get(this.key(sessionId));
    if (raw) {
      try {
        const data = JSON.parse(raw) as SessionData;
        await this.cache.srem(this.userIndexKey(data.userId), sessionId);
      } catch {
        // Corrupted — still proceed with deletion
      }
    }

    await this.cache.del(this.key(sessionId));
  }

  /**
   * IMPORTANT (Brick 9 locked rule):
   * - Update session payload WITHOUT extending its lifetime.
   */
  async updateSession(sessionId: string, partial: Partial<SessionData>): Promise<void> {
    const existing = await this.get(sessionId);
    if (!existing) return;

    const updated: SessionData = { ...existing, ...partial };

    await this.cache.set(this.key(sessionId), JSON.stringify(updated), {
      keepTtl: true,
    });
  }

  /**
   * Rotates a session ID and applies `partial` updates.
   * Returns the new sessionId, or null if the session does not exist.
   */
  async rotateSession(sessionId: string, partial: Partial<SessionData>): Promise<string | null> {
    const existing = await this.get(sessionId);
    if (!existing) return null;

    const newSessionId = randomUUID();
    const updated: SessionData = { ...existing, ...partial };

    await this.cache.set(this.key(newSessionId), JSON.stringify(updated), {
      ttlSeconds: this.ttlSeconds,
    });

    await this.cache.sadd(this.userIndexKey(updated.userId), newSessionId, {
      ttlSeconds: this.ttlSeconds,
    });

    await this.destroy(sessionId);

    return newSessionId;
  }

  /**
   * Destroys ALL sessions for a user.
   */
  async destroyAllForUser(userId: string): Promise<void> {
    const indexKey = this.userIndexKey(userId);
    const sessionIds = await this.cache.smembers(indexKey);

    await Promise.all(sessionIds.map((id) => this.cache.del(this.key(id))));
    await this.cache.del(indexKey);
  }
}
