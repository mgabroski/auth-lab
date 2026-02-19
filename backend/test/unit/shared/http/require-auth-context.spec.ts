import { describe, it, expect } from 'vitest';
import type { FastifyRequest } from 'fastify';
import { AppError } from '../../../../src/shared/http/errors';
import { requireSession } from '../../../../src/shared/http/require-auth-context';

function makeReq(authContext: unknown): FastifyRequest {
  return { authContext } as unknown as FastifyRequest;
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

  it('throws 403 when role requirement is not met', () => {
    const req = makeReq({
      sessionId: 'sess_1',
      userId: 'usr_1',
      tenantId: 'ten_1',
      membershipId: 'mem_1',
      role: 'MEMBER',
      mfaVerified: true,
    });

    try {
      requireSession(req, { role: 'ADMIN' });
    } catch (err) {
      expect(err).toBeInstanceOf(AppError);
      const e = err as AppError;
      expect(e.status).toBe(403);
      expect(e.message).toBe('Insufficient role.');
    }
  });

  it('throws 403 when MFA is required but not verified', () => {
    const req = makeReq({
      sessionId: 'sess_1',
      userId: 'usr_1',
      tenantId: 'ten_1',
      membershipId: 'mem_1',
      role: 'ADMIN',
      mfaVerified: false,
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
