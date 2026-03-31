/**
 * backend/test/e2e/auth-sso-state-abuse.spec.ts
 *
 * WHY:
 * - Stage 4 requires explicit abuse regressions for SSO state tampering.
 * - The runtime already enforces three load-bearing rules in auth.controller.ts:
 *   1. callback must include the sso-state cookie
 *   2. cookie value must exactly match the `state` query param
 *   3. encrypted state from tenant-A must not validate on tenant-B
 * - This file turns those assumptions into durable E2E proofs without changing
 *   runtime behavior.
 *
 * RULES:
 * - Keep these as black-box HTTP tests against the real Fastify app.
 * - Do not mock controller behavior — use the real SSO start path to mint the
 *   encrypted state and cookie.
 * - Assert the public-safe error contract only. Never assert on raw encrypted
 *   state internals.
 */

import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { buildTestApp } from '../helpers/build-test-app';
import { createSsoTenant, getSsoStateFromStart } from '../helpers/sso-test-fixtures';

type ErrorBody = {
  error: {
    code: string;
    message: string;
  };
};

const PROVIDERS = ['google', 'microsoft'] as const;

function expectValidationError(body: unknown, message: string) {
  expect(body).toEqual<ErrorBody>({
    error: {
      code: 'VALIDATION_ERROR',
      message,
    },
  });
}

describe('SSO callback state abuse regressions', () => {
  for (const provider of PROVIDERS) {
    it(`400 when ${provider} callback is missing the sso-state cookie`, async () => {
      const { app, deps, close } = await buildTestApp();
      const tenantKey = `missing-${provider}-${randomUUID().slice(0, 8)}`;
      const host = `${tenantKey}.localhost:3000`;

      try {
        await createSsoTenant({
          db: deps.db,
          tenantKey,
          allowedSso: [provider],
        });

        const { state } = await getSsoStateFromStart({
          app,
          host,
          provider,
        });

        const res = await app.inject({
          method: 'GET',
          url: `/auth/sso/${provider}/callback?code=fake-code&state=${encodeURIComponent(state)}`,
          headers: { host },
        });

        expect(res.statusCode).toBe(400);
        expectValidationError(
          res.json(),
          'SSO state cookie missing — possible CSRF or expired flow',
        );
      } finally {
        await close();
      }
    });

    it(`400 when ${provider} callback state query does not match the sso-state cookie`, async () => {
      const { app, deps, close } = await buildTestApp();
      const tenantKey = `mismatch-${provider}-${randomUUID().slice(0, 8)}`;
      const host = `${tenantKey}.localhost:3000`;

      try {
        await createSsoTenant({
          db: deps.db,
          tenantKey,
          allowedSso: [provider],
        });

        const { state, cookieHeader } = await getSsoStateFromStart({
          app,
          host,
          provider,
        });

        const tamperedState = `${state}tampered`;

        const res = await app.inject({
          method: 'GET',
          url: `/auth/sso/${provider}/callback?code=fake-code&state=${encodeURIComponent(tamperedState)}`,
          headers: { host, cookie: cookieHeader },
        });

        expect(res.statusCode).toBe(400);
        expectValidationError(
          res.json(),
          'SSO state mismatch — cookie does not match query parameter',
        );
      } finally {
        await close();
      }
    });

    it(`400 when ${provider} state from tenant-A is replayed on tenant-B`, async () => {
      const { app, deps, close } = await buildTestApp();
      const tenantAKey = `tenant-a-${provider}-${randomUUID().slice(0, 8)}`;
      const tenantBKey = `tenant-b-${provider}-${randomUUID().slice(0, 8)}`;
      const tenantAHost = `${tenantAKey}.localhost:3000`;
      const tenantBHost = `${tenantBKey}.localhost:3000`;

      try {
        await createSsoTenant({
          db: deps.db,
          tenantKey: tenantAKey,
          allowedSso: [provider],
        });

        await createSsoTenant({
          db: deps.db,
          tenantKey: tenantBKey,
          allowedSso: [provider],
        });

        const { state, cookieHeader } = await getSsoStateFromStart({
          app,
          host: tenantAHost,
          provider,
        });

        const res = await app.inject({
          method: 'GET',
          url: `/auth/sso/${provider}/callback?code=fake-code&state=${encodeURIComponent(state)}`,
          headers: { host: tenantBHost, cookie: cookieHeader },
        });

        expect(res.statusCode).toBe(400);
        expectValidationError(res.json(), 'Invalid or expired SSO request. Please try again.');
      } finally {
        await close();
      }
    });
  }
});
