import { Buffer } from 'node:buffer';
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import process from 'node:process';
import { URL } from 'node:url';

const port = Number(process.env.MOCK_AUTH_BACKEND_PORT ?? 3101);
const sessions = new Map();

function json(res, status, body, headers = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    ...headers,
  });
  res.end(JSON.stringify(body));
}

function noContent(res, status = 204, headers = {}) {
  res.writeHead(status, headers);
  res.end();
}

function parseCookies(header) {
  const result = {};

  if (!header) {
    return result;
  }

  for (const part of header.split(';')) {
    const [rawName, ...rawValueParts] = part.trim().split('=');
    if (!rawName) {
      continue;
    }

    result[rawName] = decodeURIComponent(rawValueParts.join('='));
  }

  return result;
}

async function readJsonBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  if (!chunks.length) {
    return {};
  }

  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function createSession(state) {
  const sid = randomUUID();
  sessions.set(sid, state);
  return sid;
}

function buildMeResponse(session) {
  return {
    user: {
      id: session.userId,
      email: session.email,
      name: session.name,
    },
    membership: {
      id: session.membershipId,
      role: session.role,
    },
    tenant: {
      id: 'tenant-1',
      key: 'acme',
      name: 'Acme',
    },
    session: {
      mfaVerified: session.mfaVerified,
      emailVerified: session.emailVerified,
    },
    nextAction: session.nextAction,
  };
}

function activeConfig() {
  return {
    tenant: {
      name: 'Acme',
      isActive: true,
      publicSignupEnabled: true,
      allowedSso: ['google'],
    },
  };
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? `127.0.0.1:${port}`}`);
    const cookies = parseCookies(req.headers.cookie);
    const sid = cookies.sid;
    const session = sid ? (sessions.get(sid) ?? null) : null;

    if (req.method === 'GET' && url.pathname === '/auth/config') {
      return json(res, 200, activeConfig());
    }

    if (req.method === 'GET' && url.pathname === '/auth/me') {
      if (!session) {
        return json(res, 401, {
          error: {
            code: 'UNAUTHORIZED',
            message: 'No active session.',
          },
        });
      }

      return json(res, 200, buildMeResponse(session));
    }

    if (req.method === 'POST' && url.pathname === '/auth/login') {
      const body = await readJsonBody(req);
      const email = String(body.email ?? '').toLowerCase();

      if (email === 'member@example.com') {
        const newSid = createSession({
          userId: 'user-member',
          membershipId: 'membership-member',
          role: 'MEMBER',
          email,
          name: 'Member User',
          mfaVerified: true,
          emailVerified: true,
          nextAction: 'NONE',
        });

        return json(
          res,
          200,
          {
            status: 'AUTHENTICATED',
            nextAction: 'NONE',
            user: { id: 'user-member', email, name: 'Member User' },
            membership: { id: 'membership-member', role: 'MEMBER' },
          },
          {
            'Set-Cookie': `sid=${newSid}; Path=/; HttpOnly; SameSite=Strict`,
          },
        );
      }

      if (email === 'admin@example.com') {
        const newSid = createSession({
          userId: 'user-admin',
          membershipId: 'membership-admin',
          role: 'ADMIN',
          email,
          name: 'Admin User',
          mfaVerified: false,
          emailVerified: true,
          nextAction: 'MFA_SETUP_REQUIRED',
        });

        return json(
          res,
          200,
          {
            status: 'AUTHENTICATED',
            nextAction: 'MFA_SETUP_REQUIRED',
            user: { id: 'user-admin', email, name: 'Admin User' },
            membership: { id: 'membership-admin', role: 'ADMIN' },
          },
          {
            'Set-Cookie': `sid=${newSid}; Path=/; HttpOnly; SameSite=Strict`,
          },
        );
      }

      return json(res, 401, {
        error: {
          code: 'UNAUTHORIZED',
          message: 'Invalid email or password. Please try again.',
        },
      });
    }

    if (req.method === 'POST' && url.pathname === '/auth/signup') {
      const body = await readJsonBody(req);
      const email = String(body.email ?? '').toLowerCase();
      const name = String(body.name ?? 'Signup User');
      const newSid = createSession({
        userId: 'user-signup',
        membershipId: 'membership-signup',
        role: 'MEMBER',
        email,
        name,
        mfaVerified: true,
        emailVerified: false,
        nextAction: 'EMAIL_VERIFICATION_REQUIRED',
      });

      return json(
        res,
        201,
        {
          status: 'EMAIL_VERIFICATION_REQUIRED',
          nextAction: 'EMAIL_VERIFICATION_REQUIRED',
          user: { id: 'user-signup', email, name },
          membership: { id: 'membership-signup', role: 'MEMBER' },
        },
        {
          'Set-Cookie': `sid=${newSid}; Path=/; HttpOnly; SameSite=Strict`,
        },
      );
    }

    if (req.method === 'POST' && url.pathname === '/auth/mfa/setup') {
      if (!session) {
        return json(res, 401, {
          error: {
            code: 'UNAUTHORIZED',
            message: 'No active session.',
          },
        });
      }

      return json(res, 200, {
        secret: 'ABCDEF123456',
        qrCodeUri: 'otpauth://totp/Hubins:admin@example.com?secret=ABCDEF123456&issuer=Hubins',
        recoveryCodes: ['code-one', 'code-two', 'code-three'],
      });
    }

    if (req.method === 'POST' && url.pathname === '/auth/mfa/verify-setup') {
      if (!session) {
        return json(res, 401, {
          error: {
            code: 'UNAUTHORIZED',
            message: 'No active session.',
          },
        });
      }

      const nextSession = {
        ...session,
        mfaVerified: true,
        nextAction: 'NONE',
      };
      sessions.set(sid, nextSession);

      return json(res, 200, {
        status: 'AUTHENTICATED',
        nextAction: 'NONE',
      });
    }

    if (req.method === 'POST' && url.pathname === '/auth/verify-email') {
      if (!session) {
        return json(res, 401, {
          error: {
            code: 'UNAUTHORIZED',
            message: 'No active session.',
          },
        });
      }

      const nextSession = {
        ...session,
        emailVerified: true,
        nextAction: 'NONE',
      };
      sessions.set(sid, nextSession);

      return json(res, 200, {
        status: 'VERIFIED',
      });
    }

    if (req.method === 'POST' && url.pathname === '/auth/resend-verification') {
      if (!session) {
        return json(res, 401, {
          error: {
            code: 'UNAUTHORIZED',
            message: 'No active session.',
          },
        });
      }

      return json(res, 200, {
        message: 'If your email is unverified, a new verification link has been sent.',
      });
    }

    if (req.method === 'POST' && url.pathname === '/auth/logout') {
      if (sid) {
        sessions.delete(sid);
      }

      return json(
        res,
        200,
        {
          message: 'Logged out.',
        },
        {
          'Set-Cookie': 'sid=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict',
        },
      );
    }

    if (req.method === 'GET' && url.pathname === '/__health') {
      return noContent(res);
    }

    return json(res, 404, {
      error: {
        code: 'NOT_FOUND',
        message: `Unhandled mock route: ${req.method} ${url.pathname}`,
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return json(res, 500, {
      error: {
        code: 'MOCK_BACKEND_ERROR',
        message,
      },
    });
  }
});

server.listen(port, '127.0.0.1', () => {
  process.stdout.write(`mock-auth-backend listening on http://127.0.0.1:${port}\n`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
  });
}
