import type { FastifyInstance } from 'fastify';
import type { Response } from 'light-my-request';
import type { DbExecutor } from '../../src/shared/db/db';
import { sql } from 'kysely';

export async function createSsoTenant(opts: {
  db: DbExecutor;
  tenantKey: string;
  allowedSso?: string[];
  allowedEmailDomains?: string[];
  memberMfaRequired?: boolean;
}) {
  return opts.db
    .insertInto('tenants')
    .values({
      key: opts.tenantKey,
      name: `Test Tenant ${opts.tenantKey}`,
      is_active: true,
      public_signup_enabled: false,
      member_mfa_required: opts.memberMfaRequired ?? false,
      allowed_email_domains: opts.allowedEmailDomains?.length
        ? sql`${JSON.stringify(opts.allowedEmailDomains)}::jsonb`
        : sql`'[]'::jsonb`,
      allowed_sso: opts.allowedSso ?? ['google', 'microsoft'],
    })
    .returning(['id', 'key'])
    .executeTakeFirstOrThrow();
}

export async function createUserWithMembership(opts: {
  db: DbExecutor;
  tenantId: string;
  email: string;
  name?: string;
  role: 'ADMIN' | 'MEMBER';
  status: 'ACTIVE' | 'INVITED' | 'SUSPENDED';
}) {
  const user = await opts.db
    .insertInto('users')
    .values({
      email: opts.email,
      name: opts.name ?? null,
    })
    .returning(['id', 'email'])
    .executeTakeFirstOrThrow();

  const membership = await opts.db
    .insertInto('memberships')
    .values({
      tenant_id: opts.tenantId,
      user_id: user.id,
      role: opts.role,
      status: opts.status,
      invited_at: new Date(),
      ...(opts.status === 'ACTIVE' ? { accepted_at: new Date() } : {}),
      ...(opts.status === 'SUSPENDED' ? { suspended_at: new Date() } : {}),
    })
    .returning(['id', 'status', 'role'])
    .executeTakeFirstOrThrow();

  return { user, membership };
}

export function buildFakeIdToken(payload: Record<string, unknown>): string {
  const header = base64UrlJson({ alg: 'none', typ: 'JWT' });
  const body = base64UrlJson(payload);
  return `${header}.${body}.fake_signature`;
}

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

export async function getSsoStateFromStart(opts: {
  app: FastifyInstance;
  host: string;
  provider: 'google' | 'microsoft';
}): Promise<{ state: string; nonce: string }> {
  const res: Response = await opts.app.inject({
    method: 'GET',
    url: `/auth/sso/${opts.provider}`,
    headers: { host: opts.host },
  });

  if (res.statusCode !== 302) {
    throw new Error(`Expected 302 from SSO start, got ${res.statusCode}. Body: ${res.body}`);
  }

  const location = res.headers.location;
  if (typeof location !== 'string') throw new Error('Location header missing in 302 response');

  const u = new URL(location, `http://${opts.host}`);
  const state = u.searchParams.get('state');
  const nonce = u.searchParams.get('nonce');

  if (!state || !nonce) throw new Error('state/nonce missing in SSO redirect URL');
  return { state, nonce };
}
