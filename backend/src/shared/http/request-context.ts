/**
 * backend/src/shared/http/request-context.ts
 *
 * WHY:
 * - Multi-tenancy requires we know which tenant/workspace a request belongs to.
 * - We also want a stable requestId for logs, debugging, auditing, and tracing.
 *
 * HOW TO USE:
 * - Registered once in app/server.ts via registerRequestContext(app).
 * - After registration, every request has `req.requestContext`.
 *
 * RULES:
 * - tenantKey can be null (e.g., localhost root, apex domain, missing/invalid Host header).
 * - All business modules must treat missing tenantKey as a hard failure at the boundary.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import { randomUUID } from 'node:crypto';

export type RequestContext = {
  requestId: string;
  host: string | null;
  tenantKey: string | null;
};

declare module 'fastify' {
  interface FastifyRequest {
    requestContext: RequestContext;
  }
}

function parseHost(rawHost: unknown): string | null {
  if (typeof rawHost !== 'string') return null;

  const trimmed = rawHost.trim();
  if (!trimmed) return null;

  // strip port if present (e.g., "tenant.localhost:3000")
  return trimmed.split(':')[0]?.toLowerCase() ?? null;
}

/**
 * Extracts tenant key from the host.
 *
 * Supported:
 * - <tenant>.localhost
 * - <tenant>.<anything>.<tld> (e.g., goodwill-ca.hubins.com)
 *
 * Returns null for:
 * - localhost
 * - apex domain (hubins.com) because there's no tenant segment
 * - invalid hosts
 */
function extractTenantKey(host: string | null): string | null {
  if (!host) return null;

  // local dev convenience
  if (host === 'localhost') return null;
  if (host.endsWith('.localhost')) {
    const [tenant] = host.split('.');
    return tenant && tenant !== 'localhost' ? tenant : null;
  }

  // prod/staging: goodwill-ca.hubins.com => goodwill-ca
  const parts = host.split('.');
  if (parts.length >= 3) {
    const candidate = parts[0];
    return candidate ? candidate : null;
  }

  // apex domain or unknown pattern
  return null;
}

export function registerRequestContext(app: FastifyInstance) {
  // We decorate the request so TypeScript + Fastify know the property exists.
  // We'll assign the real value on each request in the onRequest hook.
  app.decorateRequest('requestContext', null as unknown as RequestContext);

  // IMPORTANT: Fastify hooks must either be async OR accept `done`.
  app.addHook('onRequest', (req: FastifyRequest, _reply, done) => {
    const host = parseHost(req.headers.host);
    const tenantKey = extractTenantKey(host);

    req.requestContext = {
      requestId: randomUUID(),
      host,
      tenantKey,
    };

    done();
  });
}
