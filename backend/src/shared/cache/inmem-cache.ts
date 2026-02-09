/**
 * backend/src/shared/cache/inmem-cache.ts
 *
 * WHY:
 * - Allows tests (and local dev if Redis is down) to run without external infra.
 * - Used primarily for unit/service tests.
 *
 * HOW TO USE:
 * - const cache = new InMemCache()
 */

import type { Cache } from './cache';

type Entry = { value: string; expiresAtMs: number | null };

export class InMemCache implements Cache {
  private readonly store = new Map<string, Entry>();

  private now(): number {
    return Date.now();
  }

  private getEntry(key: string): Entry | null {
    const entry = this.store.get(key);
    if (!entry) return null;

    if (entry.expiresAtMs !== null && entry.expiresAtMs <= this.now()) {
      this.store.delete(key);
      return null;
    }

    return entry;
  }

  get(key: string): Promise<string | null> {
    const entry = this.getEntry(key);
    return Promise.resolve(entry ? entry.value : null);
  }

  set(key: string, value: string, opts?: { ttlSeconds?: number }): Promise<void> {
    const expiresAtMs = opts?.ttlSeconds ? this.now() + opts.ttlSeconds * 1000 : null;

    this.store.set(key, { value, expiresAtMs });
    return Promise.resolve();
  }

  del(key: string): Promise<void> {
    this.store.delete(key);
    return Promise.resolve();
  }

  incr(key: string, opts?: { ttlSeconds?: number }): Promise<number> {
    const entry = this.getEntry(key);
    const next = entry ? Number(entry.value) + 1 : 1;

    const expiresAtMs = opts?.ttlSeconds
      ? this.now() + opts.ttlSeconds * 1000
      : (entry?.expiresAtMs ?? null);

    this.store.set(key, { value: String(next), expiresAtMs });

    return Promise.resolve(next);
  }
}
