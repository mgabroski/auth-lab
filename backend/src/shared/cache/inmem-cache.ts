/**
 * src/shared/cache/inmem-cache.ts
 *
 * WHY:
 * - Allows tests (and local dev if Redis is down) to run without external infra.
 * - Used primarily for unit/service tests.
 *
 * HOW TO USE:
 * - const cache = new InMemCache()
 */

import type { Cache } from './cache';

type StringEntry = { value: string; expiresAtMs: number | null };

export class InMemCache implements Cache {
  private readonly store = new Map<string, StringEntry>();
  private readonly sets = new Map<string, Set<string>>();
  private readonly setExpiry = new Map<string, number | null>();

  private now(): number {
    return Date.now();
  }

  private getEntry(key: string): StringEntry | null {
    const entry = this.store.get(key);
    if (!entry) return null;

    if (entry.expiresAtMs !== null && entry.expiresAtMs <= this.now()) {
      this.store.delete(key);
      return null;
    }

    return entry;
  }

  private isSetExpired(key: string): boolean {
    const exp = this.setExpiry.get(key);
    if (exp === undefined || exp === null) return false;
    return exp <= this.now();
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
    this.sets.delete(key);
    this.setExpiry.delete(key);
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

  sadd(key: string, member: string, opts?: { ttlSeconds?: number }): Promise<void> {
    // Evict if expired
    if (this.isSetExpired(key)) {
      this.sets.delete(key);
      this.setExpiry.delete(key);
    }

    let set = this.sets.get(key);
    if (!set) {
      set = new Set<string>();
      this.sets.set(key, set);
    }
    set.add(member);

    // Refresh TTL on every sadd (same as Redis EXPIRE behaviour on SADD)
    if (opts?.ttlSeconds !== undefined) {
      this.setExpiry.set(key, this.now() + opts.ttlSeconds * 1000);
    } else if (!this.setExpiry.has(key)) {
      this.setExpiry.set(key, null);
    }

    return Promise.resolve();
  }

  smembers(key: string): Promise<string[]> {
    if (this.isSetExpired(key)) {
      this.sets.delete(key);
      this.setExpiry.delete(key);
      return Promise.resolve([]);
    }

    const set = this.sets.get(key);
    return Promise.resolve(set ? Array.from(set) : []);
  }

  srem(key: string, member: string): Promise<void> {
    if (this.isSetExpired(key)) {
      this.sets.delete(key);
      this.setExpiry.delete(key);
      return Promise.resolve();
    }

    this.sets.get(key)?.delete(member);
    return Promise.resolve();
  }
}
