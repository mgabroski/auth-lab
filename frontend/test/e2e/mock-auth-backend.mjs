import { Buffer } from 'node:buffer';
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import process from 'node:process';
import { URL } from 'node:url';

const port = Number(process.env.MOCK_AUTH_BACKEND_PORT ?? 3101);
const verificationTtlMs = 24 * 60 * 60 * 1000;
const resetTtlMs = 60 * 60 * 1000;

const tenants = {
  acme: {
    key: 'acme',
    id: 'tenant-acme',
    name: 'Acme',
    isActive: true,
    publicSignupEnabled: true,
    signupAllowed: true,
    allowedSso: ['google'],
  },
  inviteonly: {
    key: 'inviteonly',
    id: 'tenant-inviteonly',
    name: 'Invite Only',
    isActive: true,
    publicSignupEnabled: false,
    signupAllowed: false,
    allowedSso: [],
  },
};

const state = {
  sessions: new Map(),
  users: new Map(),
  verificationTokens: new Map(),
  resetTokens: new Map(),
  messages: [],
};

function buildSeedUsers() {
  return [
    {
      userId: 'user-member',
      membershipId: 'membership-member',
      tenantKey: 'acme',
      role: 'MEMBER',
      email: 'member@example.com',
      name: 'Member User',
      password: 'Password123!',
      emailVerified: true,
      mfaEnabled: false,
    },
    {
      userId: 'user-admin',
      membershipId: 'membership-admin',
      tenantKey: 'acme',
      role: 'ADMIN',
      email: 'admin@example.com',
      name: 'Admin User',
      password: 'Password123!',
      emailVerified: true,
      mfaEnabled: false,
    },
  ];
}

function resetState() {
  state.sessions.clear();
  state.users.clear();
  state.verificationTokens.clear();
  state.resetTokens.clear();
  state.messages = [];

  for (const user of buildSeedUsers()) {
    state.users.set(user.email, { ...user });
  }
}

resetState();

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

function getTenantFromHeaders(headers) {
  const forwardedHost = headers['x-forwarded-host'];
  const hostHeader = Array.isArray(forwardedHost)
    ? forwardedHost[0]
    : (forwardedHost ?? headers.host);
  const hostname = String(hostHeader ?? '')
    .split(':')[0]
    .toLowerCase();
  const subdomain = hostname.split('.')[0];

  return tenants[subdomain] ?? tenants.acme;
}

function createSession(user) {
  const sid = randomUUID();
  const nextAction = !user.emailVerified
    ? 'EMAIL_VERIFICATION_REQUIRED'
    : user.role === 'ADMIN'
      ? user.mfaEnabled
        ? 'MFA_REQUIRED'
        : 'MFA_SETUP_REQUIRED'
      : 'NONE';

  state.sessions.set(sid, {
    sid,
    userId: user.userId,
    membershipId: user.membershipId,
    role: user.role,
    email: user.email,
    name: user.name,
    tenantKey: user.tenantKey,
    emailVerified: user.emailVerified,
    mfaVerified: nextAction === 'NONE',
    nextAction,
  });

  return sid;
}

function getUserBySession(session) {
  if (!session) {
    return null;
  }

  return state.users.get(session.email) ?? null;
}

function setSessionCookie(sid) {
  return `sid=${sid}; Path=/; HttpOnly; SameSite=Strict`;
}

function clearSessionCookie() {
  return 'sid=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict';
}

function buildMeResponse(session) {
  const tenant = tenants[session.tenantKey] ?? tenants.acme;

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
      id: tenant.id,
      key: tenant.key,
      name: tenant.name,
    },
    session: {
      mfaVerified: session.mfaVerified,
      emailVerified: session.emailVerified,
    },
    nextAction: session.nextAction,
  };
}

function activeConfig(tenant) {
  return {
    tenant: {
      name: tenant.name,
      isActive: tenant.isActive,
      publicSignupEnabled: tenant.publicSignupEnabled,
      signupAllowed: tenant.signupAllowed,
      allowedSso: tenant.allowedSso,
    },
  };
}

function generateToken() {
  return randomUUID().replace(/-/g, '');
}

function createVerificationToken(user) {
  invalidateVerificationTokens(user.email);

  const token = generateToken();
  state.verificationTokens.set(token, {
    token,
    email: user.email,
    tenantKey: user.tenantKey,
    used: false,
    invalidated: false,
    expiresAt: Date.now() + verificationTtlMs,
  });

  const tenant = tenants[user.tenantKey] ?? tenants.acme;
  state.messages.push({
    type: 'email.verify',
    email: user.email,
    token,
    link: `http://${tenant.key}.localhost:3100/verify-email?token=${encodeURIComponent(token)}`,
    createdAt: Date.now(),
  });

  return token;
}

function invalidateVerificationTokens(email) {
  for (const tokenState of state.verificationTokens.values()) {
    if (tokenState.email === email && !tokenState.used) {
      tokenState.invalidated = true;
    }
  }
}

function createResetToken(user) {
  invalidateResetTokens(user.email);

  const token = generateToken();
  state.resetTokens.set(token, {
    token,
    email: user.email,
    tenantKey: user.tenantKey,
    used: false,
    invalidated: false,
    expiresAt: Date.now() + resetTtlMs,
  });

  const tenant = tenants[user.tenantKey] ?? tenants.acme;
  state.messages.push({
    type: 'password.reset',
    email: user.email,
    token,
    link: `http://${tenant.key}.localhost:3100/auth/reset-password?token=${encodeURIComponent(token)}`,
    createdAt: Date.now(),
  });

  return token;
}

function invalidateResetTokens(email) {
  for (const tokenState of state.resetTokens.values()) {
    if (tokenState.email === email && !tokenState.used) {
      tokenState.invalidated = true;
    }
  }
}

function destroySessionsForEmail(email) {
  for (const [sid, session] of state.sessions.entries()) {
    if (session.email === email) {
      state.sessions.delete(sid);
    }
  }
}

function listMessages(type, email) {
  return state.messages
    .filter((message) => (!type || message.type === type) && (!email || message.email === email))
    .sort((left, right) => left.createdAt - right.createdAt);
}

function buildAuthResponse(user) {
  const nextAction = !user.emailVerified
    ? 'EMAIL_VERIFICATION_REQUIRED'
    : user.role === 'ADMIN'
      ? user.mfaEnabled
        ? 'MFA_REQUIRED'
        : 'MFA_SETUP_REQUIRED'
      : 'NONE';

  return {
    status: nextAction === 'NONE' ? 'AUTHENTICATED' : nextAction,
    nextAction,
    user: {
      id: user.userId,
      email: user.email,
      name: user.name,
    },
    membership: {
      id: user.membershipId,
      role: user.role,
    },
  };
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? `127.0.0.1:${port}`}`);
    const tenant = getTenantFromHeaders(req.headers);
    const cookies = parseCookies(req.headers.cookie);
    const sid = cookies.sid;
    const session = sid ? (state.sessions.get(sid) ?? null) : null;

    if (req.method === 'POST' && url.pathname === '/__test/reset') {
      resetState();
      return json(res, 200, { status: 'ok' });
    }

    if (req.method === 'GET' && url.pathname === '/__mail/messages') {
      return json(res, 200, {
        messages: listMessages(url.searchParams.get('type'), url.searchParams.get('email')),
      });
    }

    if (req.method === 'POST' && url.pathname === '/__tokens/expire') {
      const body = await readJsonBody(req);
      const token = String(body.token ?? '');
      const type = String(body.type ?? '');
      const store = type === 'email.verify' ? state.verificationTokens : state.resetTokens;
      const tokenState = store.get(token);

      if (!tokenState) {
        return json(res, 404, {
          error: {
            code: 'NOT_FOUND',
            message: 'Unknown token.',
          },
        });
      }

      tokenState.expiresAt = Date.now() - 1_000;
      return json(res, 200, { status: 'expired' });
    }

    if (req.method === 'GET' && url.pathname === '/auth/config') {
      return json(res, 200, activeConfig(tenant));
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
      const password = String(body.password ?? '');
      const user = state.users.get(email);

      if (!user || user.password !== password) {
        return json(res, 401, {
          error: {
            code: 'UNAUTHORIZED',
            message: 'Invalid email or password. Please try again.',
          },
        });
      }

      const newSid = createSession(user);

      return json(res, 200, buildAuthResponse(user), {
        'Set-Cookie': setSessionCookie(newSid),
      });
    }

    if (req.method === 'POST' && url.pathname === '/auth/signup') {
      const body = await readJsonBody(req);
      const email = String(body.email ?? '').toLowerCase();
      const name = String(body.name ?? 'Signup User');
      const password = String(body.password ?? '');

      if (!tenant.signupAllowed) {
        return json(res, 403, {
          error: {
            code: 'FORBIDDEN',
            message: 'Sign up is disabled. You need an invitation to join.',
          },
        });
      }

      const user = {
        userId: `user-${randomUUID()}`,
        membershipId: `membership-${randomUUID()}`,
        tenantKey: tenant.key,
        role: 'MEMBER',
        email,
        name,
        password,
        emailVerified: false,
        mfaEnabled: false,
      };

      state.users.set(email, user);
      createVerificationToken(user);
      const newSid = createSession(user);

      return json(res, 201, buildAuthResponse(user), {
        'Set-Cookie': setSessionCookie(newSid),
      });
    }

    if (req.method === 'POST' && url.pathname === '/auth/forgot-password') {
      const body = await readJsonBody(req);
      const email = String(body.email ?? '').toLowerCase();
      const user = state.users.get(email);

      if (user) {
        createResetToken(user);
      }

      return json(res, 200, {
        message: 'If an account matches that email, a password reset link has been sent.',
      });
    }

    if (req.method === 'POST' && url.pathname === '/auth/reset-password') {
      const body = await readJsonBody(req);
      const token = String(body.token ?? '');
      const newPassword = String(body.newPassword ?? '');
      const tokenState = state.resetTokens.get(token);

      if (
        !tokenState ||
        tokenState.used ||
        tokenState.invalidated ||
        tokenState.expiresAt < Date.now()
      ) {
        return json(res, 400, {
          error: {
            code: 'BAD_REQUEST',
            message: 'This password reset link is invalid or has expired.',
          },
        });
      }

      const user = state.users.get(tokenState.email);
      if (!user) {
        return json(res, 400, {
          error: {
            code: 'BAD_REQUEST',
            message: 'This password reset link is invalid or has expired.',
          },
        });
      }

      tokenState.used = true;
      invalidateResetTokens(user.email);
      user.password = newPassword;
      destroySessionsForEmail(user.email);

      return json(res, 200, {
        message: 'Your password has been reset.',
      });
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
      state.sessions.set(sid, nextSession);

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

      const body = await readJsonBody(req);
      const token = String(body.token ?? '');
      const tokenState = state.verificationTokens.get(token);
      const user = getUserBySession(session);

      if (
        !tokenState ||
        !user ||
        tokenState.email !== session.email ||
        tokenState.used ||
        tokenState.invalidated ||
        tokenState.expiresAt < Date.now()
      ) {
        return json(res, 400, {
          error: {
            code: 'BAD_REQUEST',
            message: 'This verification link is invalid or has expired.',
          },
        });
      }

      tokenState.used = true;
      invalidateVerificationTokens(user.email);
      user.emailVerified = true;

      const nextSession = {
        ...session,
        emailVerified: true,
        nextAction: 'NONE',
      };
      state.sessions.set(sid, nextSession);

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

      const user = getUserBySession(session);
      if (user && !user.emailVerified) {
        createVerificationToken(user);
      }

      return json(res, 200, {
        message: 'If your email is unverified, a new verification link has been sent.',
      });
    }

    if (req.method === 'POST' && url.pathname === '/auth/logout') {
      if (sid) {
        state.sessions.delete(sid);
      }

      return json(
        res,
        200,
        {
          message: 'Logged out.',
        },
        {
          'Set-Cookie': clearSessionCookie(),
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
