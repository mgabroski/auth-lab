/**
 * backend/src/shared/http/request-context.ts
 *
 * WHY:
 * - Resolves the request-scoped truth the backend relies on:
 * - requestId
 * - effective host
 * - effective public origin
 * - tenantKey
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
 * a tenant-bearing Host header.
 * - If forwarded host is absent, retain the original Host so request context
 * still has a truthful authority/publicOrigin for non-tenant cases.
 *
 * REQUEST ID / CORRELATION:
 * - Accept a sanitized inbound request id from X-Request-Id or X-Correlation-Id.
 * - This lets the frontend SSR/server path propagate a stable correlation key
 * into the backend without redesigning the existing requestId plumbing.
 * - If neither header is present (or they are malformed), generate a UUID.
 * - Never trust arbitrary header values blindly: normalize shape/length first.
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

const REQUEST_ID_MAX_LENGTH = 128;
const REQUEST_ID_PATTERN = /^[A-Za-z0-9._:/=-]+$/;

function firstHeaderValue(value: string | string[] | number | undefined): string | undefined {
  if (Array.isArray(value)) {
    const first = value[0];
    return typeof first === 'number' ? String(first) : first;
  }

  if (typeof value === 'number') {
    return String(value);
  }

  return value;
}

function parseAuthority(rawHost: unknown): string | null {
  if (typeof rawHost !== 'string') return null;

  const trimmed = rawHost.trim();
  return trimmed ? trimmed.toLowerCase() : null;
}

function parseHostName(rawHost: unknown): string | null {
  const authority = parseAuthority(rawHost);
  if (!authority) return null;

  if (authority.startsWith('[')) {
    const closingBracketIndex = authority.indexOf(']');
    if (closingBracketIndex === -1) {
      return authority;
    }
    return authority.slice(0, closingBracketIndex + 1);
  }

  const portSeparatorIndex = authority.lastIndexOf(':');
  if (portSeparatorIndex === -1) {
    return authority;
  }

  return authority.slice(0, portSeparatorIndex) || authority;
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

function normalizeRequestId(rawValue: unknown): string | null {
  if (typeof rawValue !== 'string') return null;

  const candidate = rawValue.split(',')[0]?.trim();
  if (!candidate) return null;
  if (candidate.length > REQUEST_ID_MAX_LENGTH) return null;
  if (!REQUEST_ID_PATTERN.test(candidate)) return null;

  return candidate;
}

function resolveRequestId(req: FastifyRequest): string {
  const xRequestId = normalizeRequestId(firstHeaderValue(req.headers['x-request-id']));
  if (xRequestId) return xRequestId;

  const xCorrelationId = normalizeRequestId(firstHeaderValue(req.headers['x-correlation-id']));
  if (xCorrelationId) return xCorrelationId;

  return randomUUID();
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
      requestId: resolveRequestId(req),
      host: effectiveHost,
      proto,
      publicOrigin: effectiveAuthority ? `${proto}://${effectiveAuthority}` : null,
      tenantKey,
    };

    done();
  });
}
