import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { runDevSeed } from '../../src/shared/db/seed/dev-seed';
import { buildTestApp } from '../helpers/build-test-app';
import { getLatestOutboxPayload } from '../helpers/outbox-test-helpers';

const AcceptInviteResponseSchema = z.object({
  status: z.literal('ACCEPTED'),
  nextAction: z.enum(['SET_PASSWORD', 'SIGN_IN', 'MFA_SETUP_REQUIRED']),
});

const RegisterResponseSchema = z.object({
  status: z.literal('AUTHENTICATED'),
  nextAction: z.enum(['NONE', 'MFA_SETUP_REQUIRED']),
  user: z.object({
    id: z.string().uuid(),
    email: z.string().email(),
    name: z.string(),
  }),
  membership: z.object({
    id: z.string().uuid(),
    role: z.enum(['ADMIN', 'MEMBER']),
  }),
});

const AuthMeResponseSchema = z.object({
  user: z.object({
    id: z.string().uuid(),
    email: z.string().email(),
    name: z.string(),
  }),
  membership: z.object({
    id: z.string().uuid(),
    role: z.enum(['ADMIN', 'MEMBER']),
  }),
  tenant: z.object({
    id: z.string().uuid(),
    key: z.string(),
    name: z.string(),
  }),
  session: z.object({
    mfaVerified: z.boolean(),
    emailVerified: z.boolean(),
  }),
  nextAction: z.enum(['NONE', 'EMAIL_VERIFICATION_REQUIRED', 'MFA_SETUP_REQUIRED', 'MFA_REQUIRED']),
});

describe('bootstrap invite proof', () => {
  it('proves seed invite delivery artifact -> accept -> register -> session -> MFA continuation', async () => {
    const tenantKey = 'bootstrap-proof';
    const tenantName = 'Bootstrap Proof';
    const adminEmail = 'system_admin@example.com';
    const host = `${tenantKey}.localhost:3000`;

    const { app, deps, close } = await buildTestApp();

    try {
      await runDevSeed({
        db: deps.db,
        tokenHasher: deps.tokenHasher,
        passwordHasher: deps.passwordHasher,
        outboxRepo: deps.outboxRepo,
        outboxEncryption: deps.outboxEncryption,
        options: {
          tenantKey,
          tenantName,
          adminEmail,
          inviteTtlHours: 24 * 7,
        },
      });

      const inviteOutbox = await getLatestOutboxPayload({
        db: deps.db,
        outboxEncryption: deps.outboxEncryption,
        type: 'invite.created',
        tenantKey,
      });

      expect(inviteOutbox.toEmail).toBe(adminEmail.toLowerCase());

      const acceptRes = await app.inject({
        method: 'POST',
        url: '/auth/invites/accept',
        headers: { host },
        payload: { token: inviteOutbox.token },
      });

      expect(acceptRes.statusCode).toBe(200);
      const accepted = AcceptInviteResponseSchema.parse(acceptRes.json());
      expect(accepted).toEqual({
        status: 'ACCEPTED',
        nextAction: 'SET_PASSWORD',
      });

      const replayAcceptRes = await app.inject({
        method: 'POST',
        url: '/auth/invites/accept',
        headers: { host },
        payload: { token: inviteOutbox.token },
      });

      expect(replayAcceptRes.statusCode).toBe(409);
      expect(replayAcceptRes.body).toContain('Invite already accepted');

      const registerRes = await app.inject({
        method: 'POST',
        url: '/auth/register',
        headers: { host },
        payload: {
          email: adminEmail,
          password: 'Password123!',
          name: 'Bootstrap Admin',
          inviteToken: inviteOutbox.token,
        },
      });

      expect(registerRes.statusCode).toBe(201);
      const registered = RegisterResponseSchema.parse(registerRes.json());
      expect(registered.nextAction).toBe('MFA_SETUP_REQUIRED');
      expect(registered.user.email).toBe(adminEmail.toLowerCase());
      expect(registered.membership.role).toBe('ADMIN');

      const setCookieHeader = registerRes.headers['set-cookie'];
      const sessionCookie = Array.isArray(setCookieHeader)
        ? setCookieHeader.find((value) => value.includes('sid='))
        : setCookieHeader;

      expect(sessionCookie).toBeDefined();
      expect(sessionCookie).toContain('sid=');
      expect(sessionCookie).toContain('HttpOnly');

      const authMeRes = await app.inject({
        method: 'GET',
        url: '/auth/me',
        headers: { host, cookie: sessionCookie },
      });

      expect(authMeRes.statusCode).toBe(200);
      const me = AuthMeResponseSchema.parse(authMeRes.json());
      expect(me.tenant.key).toBe(tenantKey);
      expect(me.user.email).toBe(adminEmail.toLowerCase());
      expect(me.membership.role).toBe('ADMIN');
      expect(me.session.emailVerified).toBe(true);
      expect(me.session.mfaVerified).toBe(false);
      expect(me.nextAction).toBe('MFA_SETUP_REQUIRED');
    } finally {
      await close();
    }
  });
});
