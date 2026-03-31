/**
 * backend/src/shared/http/error-handler.ts
 *
 * WHY:
 * - Fastify's default error handler doesn't understand AppError.
 * - We need consistent error responses across all endpoints.
 * - Internal details (meta, stack traces) must never leak to clients.
 *
 * RESPONSIBILITIES:
 * - AppError → map .status and .code to structured HTTP response.
 * - Unexpected errors → 500 with generic message.
 * - Log all errors with request context for debugging.
 * - Record Stage 3 failure metrics with disciplined, reusable names.
 *
 * RULES:
 * - No business logic here.
 * - Never expose .meta or stack traces in responses.
 * - Log full error details (including REDACTED meta) for observability.
 * - Always use withRequestContext(req) so requestId, tenantKey, userId,
 *   and role are automatically included in every log line.
 *
 * SENTRY:
 * - AppError instances are EXPECTED application behavior and must NOT go to Sentry.
 * - Only unexpected errors are captured to Sentry.
 */

import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import * as Sentry from '@sentry/node';

import { AppError } from './errors';
import { withRequestContext } from '../logger/with-context';
import { recordHttpFailure } from '../observability/metrics';

type ErrorResponseBody = {
  error: {
    code: string;
    message: string;
  };
};

const SENSITIVE_META_KEYS = new Set([
  'token',
  'accessToken',
  'refreshToken',
  'sessionId',
  'password',
  'passwordHash',
  'inviteToken',
  'resetToken',
  'mfaSecret',
  'secret',
  'recoveryCode',
  'recoveryCodes',
  'code',
]);

function redactMeta(meta: unknown, depth = 0): unknown {
  if (depth > 6) return '[REDACTED:DEPTH]';
  if (meta === null || meta === undefined) return meta;

  if (Array.isArray(meta)) {
    return meta.map((v) => redactMeta(v, depth + 1));
  }

  if (typeof meta !== 'object') return meta;

  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(meta as Record<string, unknown>)) {
    out[k] = SENSITIVE_META_KEYS.has(k) ? '[REDACTED]' : redactMeta(v, depth + 1);
  }
  return out;
}

function buildResponse(code: string, message: string): ErrorResponseBody {
  return { error: { code, message } };
}

export function registerErrorHandler(app: FastifyInstance): void {
  app.setErrorHandler((err: Error, req: FastifyRequest, reply: FastifyReply) => {
    const log = withRequestContext(req);

    if (err instanceof AppError) {
      recordHttpFailure({
        method: req.method,
        url: req.url,
        headers: req.headers,
        statusCode: err.status,
        code: err.code,
        message: err.message,
        meta: err.meta,
      });

      log.warn('app_error', {
        event: 'app_error',
        flow: 'http.error',
        code: err.code,
        status: err.status,
        message: err.message,
        meta: redactMeta(err.meta),
      });

      return reply.status(err.status).send(buildResponse(err.code, err.message));
    }

    recordHttpFailure({
      method: req.method,
      url: req.url,
      headers: req.headers,
      statusCode: 500,
      code: 'INTERNAL',
      message: err.message,
    });

    Sentry.captureException(err, {
      extra: {
        requestId: req.requestContext?.requestId,
        tenantKey: req.requestContext?.tenantKey,
        path: req.url,
        method: req.method,
      },
    });

    log.error('unhandled_error', {
      event: 'unhandled_error',
      flow: 'http.error',
      message: err.message,
      stack: err.stack,
    });

    return reply.status(500).send(buildResponse('INTERNAL', 'Internal server error'));
  });
}
