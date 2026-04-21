/**
 * backend/src/modules/settings/gateways/sso-provider-readiness.gateway.ts
 *
 * WHY:
 * - Provides the Phase 2 runtime-readiness gateway used by the Integrations
 *   read model without making live outbound provider calls on Settings GET
 *   routes.
 * - Gives the repo one honest place to encode the current limitation: the full
 *   auth/runtime readiness snapshot refresher is not implemented yet, so
 *   Settings must surface cached/unavailable readiness rather than faking
 *   provider connectivity.
 *
 * RULES:
 * - No network calls.
 * - Cache-only / config-only truth.
 * - If the runtime snapshot is unavailable, return an explicit unavailable
 *   snapshot instead of guessing READY.
 */

import type { AppConfig } from '../../../app/config';
import type { SsoReadinessSnapshot } from '../services/settings-evaluators';

export class SsoProviderReadinessGateway {
  private readonly ttlMs: number;

  private readonly cache = new Map<'google' | 'microsoft', SsoReadinessSnapshot>();

  constructor(
    private readonly config: Pick<AppConfig, 'sso'>,
    opts?: {
      ttlMs?: number;
      now?: () => Date;
    },
  ) {
    this.ttlMs = opts?.ttlMs ?? 60_000;
    this.now = opts?.now ?? (() => new Date());
  }

  private readonly now: () => Date;

  getSnapshot(providerKey: 'google' | 'microsoft'): SsoReadinessSnapshot {
    const current = this.cache.get(providerKey);
    const now = this.now();

    if (current && now.getTime() - current.asOf.getTime() <= this.ttlMs) {
      return current;
    }

    const next = this.buildSnapshot(providerKey, now);
    this.cache.set(providerKey, next);
    return next;
  }

  private buildSnapshot(providerKey: 'google' | 'microsoft', asOf: Date): SsoReadinessSnapshot {
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
