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
import type { SessionData } from './session.types';
import { SESSION_KEY_PREFIX, SESSION_USER_INDEX_PREFIX } from './session.types';

export class SessionStore {
  constructor(
    private readonly cache: Cache,
    private readonly ttlSeconds: number,
  ) {}

  private key(sessionId: string): string {
    return `${SESSION_KEY_PREFIX}:${sessionId}`;
  }

  private userIndexKey(userId: string): string {
    return `${SESSION_USER_INDEX_PREFIX}:${userId}`;
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
    // This ensures the index doesn't expire while sessions are still alive.
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
    // Load session first to get userId for index cleanup
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
   * Updates specific fields of an existing session in place.
   * Used by MFA flows to flip `mfaVerified` from false → true
   * after successful TOTP verification or recovery code consumption.
   *
   * WHY UPDATE IN PLACE (not rotate session ID):
   * - Session ID rotation after privilege elevation is best practice against
   *   session fixation. In this threat model, fixation requires the attacker
   *   to have already planted a cookie on the victim's browser AND know their
   *   TOTP secret — a high prerequisite bar for Phase 1.
   * - Update-in-place keeps the client cookie and Redis index consistent
   *   without a remove-and-add operation.
   * - Session ID rotation is a candidate for a future hardening brick.
   *
   * RULES:
   * - Only updates the session data; TTL is refreshed to the configured session TTL
   *   to match current SessionStore semantics (create() and updateSession() both write).
   * - No-op if the session does not exist (already expired or destroyed).
   */
  async updateSession(sessionId: string, partial: Partial<SessionData>): Promise<void> {
    const existing = await this.get(sessionId);
    if (!existing) return; // session expired or does not exist — no-op

    const updated: SessionData = { ...existing, ...partial };

    // IMPORTANT (Brick 9 locked rule):
    // Update session payload WITHOUT extending its lifetime.
    await this.cache.set(this.key(sessionId), JSON.stringify(updated), {
      keepTtl: true,
    });
  }

  /**
   * Destroys ALL sessions for a user.
   *
   * WHY: Called after password reset (Brick 8) and future credential changes
   * (admin suspend, MFA revocation). An attacker who had the old password must
   * not retain access via an existing session cookie.
   *
   * HOW:
   * 1. SMEMBERS → get all session IDs registered for this user.
   * 2. DEL each session key.
   * 3. DEL the user index key.
   *
   * Stale IDs (sessions already expired naturally) are harmless — DEL on a
   * non-existent key is a no-op in Redis.
   */
  async destroyAllForUser(userId: string): Promise<void> {
    const indexKey = this.userIndexKey(userId);
    const sessionIds = await this.cache.smembers(indexKey);

    // Destroy each session (parallel for performance)
    await Promise.all(sessionIds.map((id) => this.cache.del(this.key(id))));

    // Remove the index itself
    await this.cache.del(indexKey);
  }
}
