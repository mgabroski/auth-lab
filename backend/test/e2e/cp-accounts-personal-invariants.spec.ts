import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import {
  EDITABLE_PERSONAL_FIELD_CATALOG,
  PERSONAL_FAMILY_DEFAULTS,
} from '../../src/modules/control-plane/accounts/cp-accounts.catalog';
import type { SaveCpPersonalInput } from '../../src/modules/control-plane/accounts/cp-accounts.schemas';
import { buildTestApp } from '../helpers/build-test-app';

type ErrorResponseBody = {
  error: {
    code: string;
    message: string;
  };
};

function readJson<T>(res: { json: () => unknown }): T {
  return res.json() as T;
}

function buildValidPersonalPayload(): SaveCpPersonalInput {
  return {
    families: PERSONAL_FAMILY_DEFAULTS.map((family) => ({
      familyKey: family.familyKey,
      isAllowed: family.defaultAllowed,
    })),
    fields: EDITABLE_PERSONAL_FIELD_CATALOG.map((field) => ({
      fieldKey: field.fieldKey,
      isAllowed: field.defaultAllowed,
      defaultSelected: field.defaultSelected,
    })),
  };
}

describe('cp accounts Personal backend invariants', () => {
  it('rejects direct API attempts to disable a Personal family that contains required baseline fields', async () => {
    const { app, close, reset } = await buildTestApp();
    const accountKey = `qa-personal-inv-${randomUUID().slice(0, 8)}`;

    try {
      await reset();

      const createRes = await app.inject({
        method: 'POST',
        url: '/cp/accounts',
        payload: {
          accountName: 'QA Personal Invariants',
          accountKey,
        },
      });

      expect(createRes.statusCode).toBe(201);

      const modulesRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/modules`,
        payload: {
          modules: {
            personal: true,
            documents: false,
            benefits: false,
            payments: false,
          },
        },
      });

      expect(modulesRes.statusCode).toBe(200);

      const payload = buildValidPersonalPayload();
      payload.families = payload.families.map((family) =>
        family.familyKey === 'identity' ? { ...family, isAllowed: false } : family,
      );

      const personalRes = await app.inject({
        method: 'PUT',
        url: `/cp/accounts/${accountKey}/modules/personal`,
        payload,
      });

      expect(personalRes.statusCode).toBe(400);
      expect(readJson<ErrorResponseBody>(personalRes)).toEqual({
        error: {
          code: 'VALIDATION_ERROR',
          message:
            'Personal families that contain required baseline or system-managed fields cannot be disabled.',
        },
      });
    } finally {
      await close();
    }
  });
});
