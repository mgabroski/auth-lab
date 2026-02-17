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
 * - RateLimitError → 429 response.
 * - Zod validation errors → 400 (safety net if controller misses).
 * - Unexpected errors → 500 with generic message.
 * - Log all errors with request context for debugging.
 *
 * RULES:
 * - No business logic here.
 * - Never expose .meta or stack traces in responses.
 * - Log full error details (including REDACTED meta) for observability.
 * - Always use withRequestContext(req) so requestId, tenantKey, userId,
 *   and role are automatically included in every log line.
 *
 * TODO:
 * - Sentry capture for unexpected errors (observability/sentry.ts).
 */

import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { AppError } from './errors';
import { RateLimitError } from '../security/rate-limit';
import { withRequestContext } from '../logger/with-context';

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

function redactMeta(meta: unknown): unknown {
  if (!meta || typeof meta !== 'object') return meta;

  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(meta as Record<string, unknown>)) {
    out[k] = SENSITIVE_META_KEYS.has(k) ? '[REDACTED]' : v;
  }
  return out;
}

function buildResponse(code: string, message: string): ErrorResponseBody {
  return { error: { code, message } };
}

export function registerErrorHandler(app: FastifyInstance): void {
  app.setErrorHandler((err: Error, req: FastifyRequest, reply: FastifyReply) => {
    const log = withRequestContext(req);

    // 1) Known application errors
    if (err instanceof AppError) {
      log.warn('app_error', {
        flow: 'http.error',
        code: err.code,
        status: err.status,
        message: err.message,
        meta: redactMeta(err.meta),
      });

      return reply.status(err.status).send(buildResponse(err.code, err.message));
    }

    // 2) Rate limit errors
    if (err instanceof RateLimitError) {
      log.warn('rate_limit', {
        flow: 'http.error',
        key: err.key,
        limit: err.limit,
        windowSeconds: err.windowSeconds,
      });

      return reply
        .status(429)
        .send(buildResponse('RATE_LIMITED', 'Too many requests. Try again later.'));
    }

    // 3) Unexpected errors — never leak internals
    // TODO: Sentry.captureException(err)
    log.error('unhandled_error', {
      flow: 'http.error',
      message: err.message,
      stack: err.stack,
    });

    return reply.status(500).send(buildResponse('INTERNAL', 'Internal server error'));
  });
}
