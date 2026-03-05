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
 * X10 — Sentry capture for unhandled 500 errors only:
 * - AppError instances are EXPECTED application behavior (auth failures,
 *   validation errors, rate limits, etc.). They are NOT bugs. They must
 *   NOT be sent to Sentry — capturing them would create noise that drowns
 *   out real incidents.
 * - Only the "unexpected errors" branch (non-AppError, non-ZodError)
 *   captures to Sentry. This is the branch that indicates a real bug.
 * - If SENTRY_DSN is unset (dev, CI, test), Sentry.init() is never called
 *   (see server.ts) and Sentry.captureException() is a safe no-op.
 *   Zero behavior or test changes in those environments.
 */

import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import * as Sentry from '@sentry/node';
import { AppError } from './errors';
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

/**
 * Redacts sensitive fields in meta recursively.
 *
 * WHY:
 * - Meta objects often contain nested payloads (eg. { token: { raw: '...' } }).
 * - A shallow redact leaks nested secrets during unexpected failures.
 *
 * RULES:
 * - Preserve shape; only replace values.
 * - Depth-limited to avoid pathological objects.
 */
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

    // 1) Known application errors (includes rate limit — AppError.rateLimited())
    //    AppError = expected application behavior, NOT a bug.
    //    Must NOT be sent to Sentry — would create noise that drowns out real incidents.
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

    // 2) Unexpected errors — a real bug reached the handler.
    //    X10: Capture to Sentry so on-call gets an immediate signal.
    //    When SENTRY_DSN is unset, captureException() is a no-op (Sentry never initialised).
    Sentry.captureException(err, {
      extra: {
        requestId: req.requestContext?.requestId,
        tenantKey: req.requestContext?.tenantKey,
        path: req.url,
        method: req.method,
      },
    });

    log.error('unhandled_error', {
      flow: 'http.error',
      message: err.message,
      stack: err.stack,
    });

    return reply.status(500).send(buildResponse('INTERNAL', 'Internal server error'));
  });
}
