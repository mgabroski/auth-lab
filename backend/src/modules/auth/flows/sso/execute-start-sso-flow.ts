/**
 * src/modules/auth/flows/sso/execute-start-sso-flow.ts
 *
 * WHY:
 * - startSso owns rate limiting and URL construction. Per ER-16/ER-18
 *   service mutation methods must be one-liners; orchestration belongs here.
 *
 * RULES:
 * - Rate limit before any work (ER-19).
 * - No transaction needed — no DB writes.
 * - No audit event — redirect initiation is not a security-significant action.
 *
 * TOPOLOGY UPDATE:
 * - Prefer the real public request origin (tenant subdomain) when building the
 *   OAuth callback URI. This removes the last major dependency on one global
 *   SSO redirect base for all tenants.
 * - Keep `redirectBaseUrl` as a controlled fallback for environments where the
 *   public request origin is unavailable.
 * - Return `ssoState` so the controller can bind the browser to the callback via
 *   the SameSite=Lax sso-state cookie.
 */

import type { TokenHasher } from '../../../../shared/security/token-hasher';
import type { RateLimiter } from '../../../../shared/security/rate-limit';
import type { EncryptionService } from '../../../../shared/security/encryption';
import type { SsoProvider } from '../../helpers/sso-state';
import type { SsoProviderRegistry } from '../../sso/sso-provider-registry';
import { buildEncryptedSsoState } from '../../helpers/sso-state';
import { AUTH_RATE_LIMITS } from '../../auth.constants';

export type StartSsoFlowParams = {
  tenantKey: string;
  provider: SsoProvider;
  requestId: string;
  requestPublicOrigin: string | null;
  returnTo?: string;
  ip: string;
};

function normalizeOrigin(origin: string): string {
  return origin.replace(/\/+$/g, '');
}

function buildCallbackUri(input: {
  provider: SsoProvider;
  requestPublicOrigin: string | null;
  redirectBaseUrl: string;
}): string {
  if (input.requestPublicOrigin) {
    return `${normalizeOrigin(input.requestPublicOrigin)}/api/auth/sso/${input.provider}/callback`;
  }

  return `${input.redirectBaseUrl.replace(/\/+$/, '')}/auth/sso/${input.provider}/callback`;
}

export async function executeStartSsoFlow(
  deps: {
    tokenHasher: TokenHasher;
    rateLimiter: RateLimiter;
    sso: {
      stateEncryptionService: EncryptionService;
      redirectBaseUrl: string;
      providerRegistry: SsoProviderRegistry;
    };
  },
  params: StartSsoFlowParams,
): Promise<{ redirectTo: string; ssoState: string }> {
  const ipKey = deps.tokenHasher.hash(params.ip);

  // ── Rate limit — before any work (ER-19) ─────────────────────────────
  await deps.rateLimiter.hitOrThrow({
    key: `sso-start:ip:${ipKey}`,
    ...AUTH_RATE_LIMITS.ssoStart.perIp,
  });

  const redirectUri = buildCallbackUri({
    provider: params.provider,
    requestPublicOrigin: params.requestPublicOrigin,
    redirectBaseUrl: deps.sso.redirectBaseUrl,
  });

  const adapter = deps.sso.providerRegistry.getOrThrow(params.provider);

  const { state: ssoState, nonce } = buildEncryptedSsoState({
    encryptionService: deps.sso.stateEncryptionService,
    provider: params.provider,
    tenantKey: params.tenantKey,
    requestId: params.requestId,
    redirectUri,
    returnTo: params.returnTo,
  });

  const redirectTo = adapter.buildAuthorizationUrl({ redirectUri, state: ssoState, nonce });

  return { redirectTo, ssoState };
}
