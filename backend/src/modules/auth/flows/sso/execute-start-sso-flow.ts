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
 */

import type { TokenHasher } from '../../../../shared/security/token-hasher';
import type { RateLimiter } from '../../../../shared/security/rate-limit';
import type { EncryptionService } from '../../../../shared/security/encryption';
import type { SsoProvider } from '../../helpers/sso-state';
import type { SsoProviderRegistry } from '../../sso/sso-provider-registry';
import { buildSsoAuthorizationUrl } from '../../helpers/sso-authorize-url';
import { AUTH_RATE_LIMITS } from '../../auth.constants';

export type StartSsoFlowParams = {
  tenantKey: string;
  provider: SsoProvider;
  requestId: string;
  returnTo?: string;
  ip: string;
};

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
): Promise<{ redirectTo: string }> {
  const ipKey = deps.tokenHasher.hash(params.ip);

  // ── Rate limit — before any work (ER-19) ─────────────────────────────
  await deps.rateLimiter.hitOrThrow({
    key: `sso-start:ip:${ipKey}`,
    ...AUTH_RATE_LIMITS.ssoStart.perIp,
  });

  const redirectTo = buildSsoAuthorizationUrl({
    provider: params.provider,
    tenantKey: params.tenantKey,
    requestId: params.requestId,
    returnTo: params.returnTo,
    encryptionService: deps.sso.stateEncryptionService,
    redirectBaseUrl: deps.sso.redirectBaseUrl,
    providerRegistry: deps.sso.providerRegistry,
  });

  return { redirectTo };
}
