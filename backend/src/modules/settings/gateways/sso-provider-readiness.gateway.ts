/**
 * backend/src/modules/settings/gateways/sso-provider-readiness.gateway.ts
 *
 * WHY:
 * - Provides the runtime-readiness gateway used by the Integrations read model
 *   without making live outbound provider calls on Settings GET routes.
 * - Encodes the current repo limitation honestly: external-provider readiness is
 *   not backed by a reusable auth/runtime snapshot refresher yet, so Settings
 *   reports unavailable/stale snapshot truth instead of pretending providers are
 *   connected. The deferred production refresher is tracked in
 *   docs/quality-exceptions.md (QE-0001).
 *
 * RULES:
 * - No network calls.
 * - Cache-only / config-only truth.
 * - If runtime readiness is unavailable or stale, return explicit degraded
 *   truth that downstream evaluators can fail closed with.
 */

import type { AppConfig } from '../../../app/config';
import type { SsoReadinessSnapshot } from '../services/settings-evaluators';

type SsoProviderKey = 'google' | 'microsoft';

type SsoProviderReadinessGatewayOpts = {
  ttlMs?: number;
  now?: () => Date;
  initialSnapshots?: Partial<Record<SsoProviderKey, SsoReadinessSnapshot>>;
};

export class SsoProviderReadinessGateway {
  private readonly ttlMs: number;

  private readonly cache = new Map<SsoProviderKey, SsoReadinessSnapshot>();

  private readonly now: () => Date;

  constructor(
    private readonly config: Pick<AppConfig, 'sso'>,
    opts?: SsoProviderReadinessGatewayOpts,
  ) {
    this.ttlMs = opts?.ttlMs ?? 60_000;
    this.now = opts?.now ?? (() => new Date());

    for (const providerKey of ['google', 'microsoft'] as const) {
      const snapshot = opts?.initialSnapshots?.[providerKey];
      if (snapshot) {
        this.cache.set(providerKey, snapshot);
      }
    }
  }

  /**
   * Injection point for the future auth/runtime readiness refresher.
   *
   * Settings deliberately does not call providers live. Until the production
   * refresher is implemented, this method is used by tests and local runtime
   * wiring only; missing snapshots fail closed as SNAPSHOT_UNAVAILABLE.
   */
  upsertRuntimeSnapshot(snapshot: SsoReadinessSnapshot): void {
    this.cache.set(snapshot.providerKey, snapshot);
  }

  getSnapshot(providerKey: SsoProviderKey): SsoReadinessSnapshot {
    const current = this.cache.get(providerKey);
    const now = this.now();

    if (current) {
      const ageMs = now.getTime() - current.asOf.getTime();
      if (ageMs <= this.ttlMs) {
        return current;
      }

      return {
        ...current,
        status: 'STALE',
        detail: `${providerLabel(providerKey)} SSO runtime readiness snapshot is stale. Last snapshot age is ${ageMs}ms, beyond the ${this.ttlMs}ms freshness window.`,
      };
    }

    const next = this.buildBootstrapSnapshot(providerKey, now);
    this.cache.set(providerKey, next);
    return next;
  }

  private buildBootstrapSnapshot(providerKey: SsoProviderKey, asOf: Date): SsoReadinessSnapshot {
    if (this.config.sso.localOidc) {
      return {
        providerKey,
        status: 'READY',
        asOf,
        detail: 'Local OIDC provider is enabled for this runtime.',
      };
    }

    return {
      providerKey,
      status: 'SNAPSHOT_UNAVAILABLE',
      asOf,
      detail:
        'Auth/runtime readiness snapshot refresh is not yet implemented for external providers in this repo. Settings GET routes must fail closed instead of probing providers live.',
    };
  }
}

function providerLabel(providerKey: SsoProviderKey): string {
  return providerKey === 'google' ? 'Google' : 'Microsoft';
}
