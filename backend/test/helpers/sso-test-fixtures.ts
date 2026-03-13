import type { FastifyInstance } from 'fastify';
import type { Response } from 'light-my-request';
import { sql } from 'kysely';

import type { DbExecutor } from '../../src/shared/db/db';

/**
 * Creates a tenant specifically configured for SSO testing.
 */
export async function createSsoTenant(opts: {
  db: DbExecutor;
  tenantKey: string;
  allowedSso?: string[];
  allowedEmailDomains?: string[];
  memberMfaRequired?: boolean;
  publicSignupEnabled?: boolean;
  adminInviteRequired?: boolean;
}) {
  return opts.db
    .insertInto('tenants')
    .values({
      key: opts.tenantKey,
      name: `Test Tenant ${opts.tenantKey}`,
      is_active: true,
      public_signup_enabled: opts.publicSignupEnabled ?? false,
      admin_invite_required: opts.adminInviteRequired ?? false,
      member_mfa_required: opts.memberMfaRequired ?? false,
      allowed_email_domains: opts.allowedEmailDomains?.length
        ? sql`${JSON.stringify(opts.allowedEmailDomains)}::jsonb`
        : sql`'[]'::jsonb`,
      allowed_sso: opts.allowedSso ?? ['google', 'microsoft'],
    })
    .returning(['id', 'key'])
    .executeTakeFirstOrThrow();
}

/**
 * Creates a user and an associated membership record in a single flow.
 */
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

/**
 * Creates an invite row for SSO / signup policy-path tests.
 */
export async function createInvite(opts: {
  db: DbExecutor;
  tenantId: string;
  email: string;
  role: 'ADMIN' | 'MEMBER';
  status?: 'PENDING' | 'ACCEPTED' | 'CANCELLED' | 'EXPIRED';
  expiresAt?: Date;
  usedAt?: Date | null;
}) {
  return opts.db
    .insertInto('invites')
    .values({
      tenant_id: opts.tenantId,
      email: opts.email.toLowerCase(),
      role: opts.role,
      status: opts.status ?? 'PENDING',
      token_hash: `token-${Math.random().toString(36).slice(2)}`,
      expires_at: opts.expiresAt ?? new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      used_at: opts.usedAt ?? null,
      created_by_user_id: null,
    })
    .returning(['id', 'status', 'role'])
    .executeTakeFirstOrThrow();
}

/**
 * Generates an unsigned, Base64Url encoded JWT for mocking SSO providers.
 */
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

/**
 * Simulates the initial GET request to an SSO endpoint and extracts
 * the required state, nonce, and session cookies for the callback phase.
 */
export async function getSsoStateFromStart(opts: {
  app: FastifyInstance;
  host: string;
  provider: 'google' | 'microsoft';
}): Promise<{ state: string; nonce: string; cookieHeader: string }> {
  const res: Response = await opts.app.inject({
    method: 'GET',
    url: `/auth/sso/${opts.provider}`,
    headers: { host: opts.host },
  });

  if (res.statusCode !== 302) {
    throw new Error(`Expected 302 from SSO start, got ${res.statusCode}. Body: ${res.body}`);
  }

  const location = res.headers.location;
  if (typeof location !== 'string') {
    throw new Error('Location header missing in 302 response');
  }

  const url = new URL(location, `http://${opts.host}`);
  const state = url.searchParams.get('state');
  const nonce = url.searchParams.get('nonce');

  if (!state || !nonce) {
    throw new Error('state/nonce missing in SSO redirect URL');
  }

  const rawSetCookie = res.headers['set-cookie'];
  const setCookie = Array.isArray(rawSetCookie) ? rawSetCookie[0] : rawSetCookie;

  if (typeof setCookie !== 'string' || !setCookie.length) {
    throw new Error('Set-Cookie header missing in SSO start response');
  }

  const cookieHeader = setCookie.split(';')[0] ?? '';
  if (!cookieHeader) {
    throw new Error('Unable to extract SSO state cookie from Set-Cookie header');
  }

  return { state, nonce, cookieHeader };
}
