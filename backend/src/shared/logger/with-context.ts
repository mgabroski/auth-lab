/**
 * backend/src/shared/logger/with-context.ts
 *
 * WHY:
 * - Most logs should include requestId + tenantKey so we can trace a full request.
 * - We don't want every handler repeating the same fields manually.
 *
 * HOW TO USE:
 * - In a request handler: `withRequestContext(req).info('msg', { flow: '...' })`
 * - This preserves our required fields: requestId, tenantKey, host
 */

import type { FastifyRequest } from 'fastify';
import { logger } from './logger';

type LogMeta = Record<string, unknown>;

export function withRequestContext(req: FastifyRequest) {
  const base = {
    requestId: req.requestContext?.requestId,
    tenantKey: req.requestContext?.tenantKey,
    host: req.requestContext?.host,

    userId: req.authContext?.userId ?? null,
    membershipId: req.authContext?.membershipId ?? null,
    role: req.authContext?.role ?? null,
  };

  return {
    info: (msg: string, meta: LogMeta = {}) => logger.info(msg, { ...base, ...meta }),
    warn: (msg: string, meta: LogMeta = {}) => logger.warn(msg, { ...base, ...meta }),
    error: (msg: string, meta: LogMeta = {}) => logger.error(msg, { ...base, ...meta }),
    debug: (msg: string, meta: LogMeta = {}) => logger.debug(msg, { ...base, ...meta }),
  };
}
