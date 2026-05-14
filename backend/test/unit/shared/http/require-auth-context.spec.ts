import { describe, it, expect } from 'vitest';
import type { FastifyRequest } from 'fastify';
import { AppError } from '../../../../src/shared/http/errors';
import { requireSession } from '../../../../src/shared/http/require-auth-context';
import type { Role } from '../../../../src/shared/http/auth-context';

function makeReq(authContext: unknown): FastifyRequest {
  return { authContext } as unknown as FastifyRequest;
}

function makeAuthContext(role: Role): unknown {
  return {
    sessionId: `sess_${role.toLowerCase()}`,
    userId: `usr_${role.toLowerCase()}`,
    tenantId: 'ten_1',
    membershipId: `mem_${role.toLowerCase()}`,
    role,
    mfaVerified: true,
    emailVerified: true,
  };
}

describe('requireSession', () => {
  it('throws 401 when no session is present', () => {
    expect(() => requireSession(makeReq(null))).toThrowError(AppError);

    try {
      requireSession(makeReq(null));
    } catch (err) {
      expect(err).toBeInstanceOf(AppError);
      const e = err as AppError;
      expect(e.status).toBe(401);
      expect(e.message).toBe('Authentication required');
    }
  });

  it.each<Role>(['ADMIN', 'AGENT', 'USER'])('returns canonical %s session context', (role) => {
    const ctx = requireSession(makeReq(makeAuthContext(role)));

    expect(ctx.role).toBe(role);
    expect(ctx.sessionId).toBe(`sess_${role.toLowerCase()}`);
    expect(ctx.membershipId).toBe(`mem_${role.toLowerCase()}`);
  });

  it.each<Role>(['AGENT', 'USER'])('throws 403 when %s requests an ADMIN-only guard', (role) => {
    try {
      requireSession(makeReq(makeAuthContext(role)), { role: 'ADMIN' });
    } catch (err) {
      expect(err).toBeInstanceOf(AppError);
      const e = err as AppError;
      expect(e.status).toBe(403);
      expect(e.message).toBe('Insufficient role.');
    }
  });

  it('allows ADMIN through an ADMIN-only guard', () => {
    const ctx = requireSession(makeReq(makeAuthContext('ADMIN')), { role: 'ADMIN' });

    expect(ctx.role).toBe('ADMIN');
  });

  it('throws 403 when MFA is required but not verified', () => {
    const req = makeReq({
      sessionId: 'sess_1',
      userId: 'usr_1',
      tenantId: 'ten_1',
      membershipId: 'mem_1',
      role: 'ADMIN',
      mfaVerified: false,
      emailVerified: true,
    });

    try {
      requireSession(req, { requireMfa: true });
    } catch (err) {
      expect(err).toBeInstanceOf(AppError);
      const e = err as AppError;
      expect(e.status).toBe(403);
      expect(e.message).toBe('MFA verification required.');
    }
  });
});
