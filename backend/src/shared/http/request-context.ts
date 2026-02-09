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
  if (typeof rawHost !== 'string' || rawHost.trim() === '') return null;
  return rawHost.split(':')[0].toLowerCase();
}

function extractTenantKey(host: string | null): string | null {
  if (!host) return null;

  if (host === 'localhost') return null;
  if (host.endsWith('.localhost')) {
    const parts = host.split('.');
    return parts.length >= 2 ? parts[0] : null;
  }

  const parts = host.split('.');
  if (parts.length >= 3) return parts[0];

  return null;
}

export function registerRequestContext(app: FastifyInstance) {
  app.decorateRequest('requestContext', null);

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
