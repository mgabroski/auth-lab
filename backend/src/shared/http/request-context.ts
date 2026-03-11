/**
 * backend/src/shared/http/request-context.ts
 *
 * WHY:
 * - Resolves the request-scoped truth the backend relies on:
 *   - requestId
 *   - effective host
 *   - effective public origin
 *   - tenantKey
 * - Multi-tenancy depends on host/subdomain-derived tenant identity.
 * - Topology-aware flows such as SSO start need the effective public origin.
 *
 * RULES:
 * - tenantKey may be null for apex/no-tenant hosts.
 * - business modules must treat missing tenantKey as a boundary failure where required
 * - publicOrigin is routing/topology metadata, not an auth decision by itself
 *
 * HOST RESOLUTION:
 * - Prefer Host when it already contains tenant context.
 * - Fall back to X-Forwarded-Host when SSR/direct backend calls do not preserve
 *   a tenant-bearing Host header.
 * - If forwarded host is absent, retain the original Host so request context
 *   still has a truthful authority/publicOrigin for non-tenant cases.
 */

import { randomUUID } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';

export type RequestContext = {
  requestId: string;
  host: string | null;
  proto: 'http' | 'https';
  publicOrigin: string | null;
  tenantKey: string | null;
};

declare module 'fastify' {
  interface FastifyRequest {
    requestContext: RequestContext;
  }
}

function firstHeaderValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function parseAuthority(rawHost: unknown): string | null {
  if (typeof rawHost !== 'string') return null;

  const trimmed = rawHost.trim();
  return trimmed ? trimmed.toLowerCase() : null;
}

function parseHostName(rawHost: unknown): string | null {
  const authority = parseAuthority(rawHost);
  if (!authority) return null;

  return authority.split(':')[0] ?? null;
}

function parseForwardedProto(rawProto: unknown): 'http' | 'https' {
  let value: string | undefined;

  if (typeof rawProto === 'string') {
    value = rawProto;
  } else if (Array.isArray(rawProto) && typeof rawProto[0] === 'string') {
    value = rawProto[0];
  }

  if (!value) return 'http';

  const candidate = value.split(',')[0]?.trim().toLowerCase();
  return candidate === 'https' ? 'https' : 'http';
}

function extractTenantKey(host: string | null): string | null {
  if (!host) return null;

  if (host === 'localhost') return null;

  if (host.endsWith('.localhost')) {
    const [tenant] = host.split('.');
    return tenant && tenant !== 'localhost' ? tenant : null;
  }

  const parts = host.split('.');
  if (parts.length >= 3) {
    const candidate = parts[0];
    return candidate ? candidate : null;
  }

  return null;
}

export function registerRequestContext(app: FastifyInstance): void {
  app.decorateRequest('requestContext', null as unknown as RequestContext);

  app.addHook('onRequest', (req: FastifyRequest, _reply, done) => {
    const rawHost = req.headers.host;
    const rawForwardedHost = firstHeaderValue(req.headers['x-forwarded-host']);
    const rawForwardedProto = req.headers['x-forwarded-proto'];

    const authorityFromHost = parseAuthority(rawHost);
    const hostFromHost = parseHostName(rawHost);
    const tenantFromHost = extractTenantKey(hostFromHost);

    const authorityFromForwardedHost = parseAuthority(rawForwardedHost);
    const hostFromForwardedHost = parseHostName(rawForwardedHost);
    const tenantFromForwardedHost = extractTenantKey(hostFromForwardedHost);

    const effectiveAuthority = tenantFromHost
      ? authorityFromHost
      : (authorityFromForwardedHost ?? authorityFromHost);

    const effectiveHost = tenantFromHost ? hostFromHost : (hostFromForwardedHost ?? hostFromHost);

    const tenantKey = tenantFromHost ?? tenantFromForwardedHost;
    const proto = parseForwardedProto(rawForwardedProto);

    req.requestContext = {
      requestId: randomUUID(),
      host: effectiveHost,
      proto,
      publicOrigin: effectiveAuthority ? `${proto}://${effectiveAuthority}` : null,
      tenantKey,
    };

    done();
  });
}
