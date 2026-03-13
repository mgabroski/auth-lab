import { describe, it, expect } from 'vitest';
import { randomUUID } from 'node:crypto';
import { sql } from 'kysely';

import { buildTestApp } from '../helpers/build-test-app';
import { getTenantByKey } from '../../src/modules/tenants/queries/tenant.queries';

describe('tenant queries', () => {
  it('hydrates adminInviteRequired as an explicit tenant policy field', async () => {
    const { deps, close } = await buildTestApp();
    const tenantKey = `tenant-${randomUUID().slice(0, 8)}`;

    try {
      await deps.db
        .insertInto('tenants')
        .values({
          key: tenantKey,
          name: 'Tenant Policy',
          is_active: true,
          public_signup_enabled: true,
          admin_invite_required: true,
          member_mfa_required: false,
          allowed_email_domains: sql`'["acme.com"]'::jsonb`,
          allowed_sso: ['microsoft', 'google'],
        })
        .executeTakeFirstOrThrow();

      const tenant = await getTenantByKey(deps.db, tenantKey);
      expect(tenant).toBeDefined();
      expect(tenant!.adminInviteRequired).toBe(true);
      expect(tenant!.publicSignupEnabled).toBe(true);
      expect(tenant!.allowedEmailDomains).toEqual(['acme.com']);
      expect(tenant!.allowedSso).toEqual(['microsoft', 'google']);
    } finally {
      await close();
    }
  });
});
