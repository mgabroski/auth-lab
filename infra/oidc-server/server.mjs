/**
 * infra/oidc-server/server.mjs
 *
 * WHY:
 * - CI cannot use real Google/Microsoft OAuth (no browser, no real accounts,
 *   rate limits). Backend unit + E2E tests use FakeSsoAdapter which bypasses
 *   real JWKS fetch and JWT signature verification entirely.
 * - This server closes the proof gap: it issues real RS256-signed JWTs from a
 *   real JWKS endpoint so the backend's jose jwtVerify() call exercises the
 *   actual cryptographic path (JWKS HTTP fetch → signature check → iss/aud/exp
 *   enforcement → nonce check) against local material.
 *
 * WHAT IT PROVIDES:
 *   GET  /.well-known/openid-configuration  OIDC discovery document
 *   GET  /.well-known/jwks.json             Real RS256 JWKS (ephemeral key)
 *   POST /token                             OAuth2 code exchange → real RS256 id_token
 *   POST /code                              CI test helper: register identity → code
 *
 * SECURITY SCOPE:
 * - CI only. Ephemeral RSA-2048 key is generated at startup, held in memory,
 *   never persisted. Tokens expire in 5 minutes. Codes expire in 2 minutes.
 * - Zero npm dependencies. Node.js 20 built-ins only.
 *
 * PORT / ENV:
 *   LOCAL_OIDC_PORT      default 9998
 *   LOCAL_OIDC_ISSUER    default http://localhost:<port>
 *                        In CI Docker network: http://local-oidc:9998
 *   LOCAL_OIDC_CLIENT_ID default local-oidc-ci-client
 */

import { createServer } from 'node:http';
import {
  generateKeyPairSync,
  createSign,
  createPublicKey,
  createPrivateKey,
  randomBytes,
} from 'node:crypto';

// ── Configuration ─────────────────────────────────────────────────────────────

const PORT = Number(process.env.LOCAL_OIDC_PORT ?? 9998);
const ISSUER = (process.env.LOCAL_OIDC_ISSUER ?? `http://localhost:${PORT}`).replace(/\/$/, '');
const CLIENT_ID = process.env.LOCAL_OIDC_CLIENT_ID ?? 'local-oidc-ci-client';
const KID = 'ci-key-1';

// ── Ephemeral RSA-2048 keypair ────────────────────────────────────────────────

const { privateKey: privDer, publicKey: pubDer } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'der' },
  privateKeyEncoding: { type: 'pkcs8', format: 'der' },
});

const privKeyObj = createPrivateKey({ key: privDer, format: 'der', type: 'pkcs8' });
const pubKeyObj = createPublicKey({ key: pubDer, format: 'der', type: 'spki' });

// Node 15+ supports JWK export from KeyObject.
const jwkPub = pubKeyObj.export({ format: 'jwk' });

const JWKS_DOC = {
  keys: [
    {
      kty: 'RSA',
      use: 'sig',
      alg: 'RS256',
      kid: KID,
      n: jwkPub.n,
      e: jwkPub.e,
    },
  ],
};

// ── In-memory code store ──────────────────────────────────────────────────────
// Map<code, { payload, expiresAt }>. Codes are single-use, 2-minute TTL.
const codeStore = new Map();

// ── Utilities ─────────────────────────────────────────────────────────────────

function base64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function generateCode() {
  return base64url(randomBytes(24));
}

function buildIdToken(claimsObj) {
  const header = JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: KID });
  const claims = JSON.stringify(claimsObj);
  const signingInput = `${base64url(Buffer.from(header))}.${base64url(Buffer.from(claims))}`;
  const signer = createSign('RSA-SHA256');
  signer.update(signingInput);
  return `${signingInput}.${base64url(signer.sign(privKeyObj))}`;
}

function respond(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(json),
    'Cache-Control': 'no-store',
    Pragma: 'no-cache',
  });
  res.end(json);
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

function pruneExpired() {
  const now = Date.now();
  for (const [k, v] of codeStore) {
    if (v.expiresAt < now) codeStore.delete(k);
  }
}

// ── Route handlers ────────────────────────────────────────────────────────────

function handleDiscovery(_req, res) {
  respond(res, 200, {
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
    jwks_uri: `${ISSUER}/.well-known/jwks.json`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'email', 'profile'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
    claims_supported: [
      'sub',
      'email',
      'email_verified',
      'name',
      'nonce',
      'iss',
      'aud',
      'exp',
      'iat',
    ],
  });
}

function handleJwks(_req, res) {
  respond(res, 200, JWKS_DOC);
}

/**
 * POST /code  —  CI test helper (not a standard OIDC endpoint).
 *
 * WHY: Playwright tests running in CI cannot drive a real browser OAuth redirect.
 * This endpoint lets test code register a desired identity payload (email, sub,
 * nonce, etc.) and receive a short-lived authorization_code that encodes it.
 * That code is then injected into the backend SSO callback URL directly,
 * triggering the full backend callback flow — including the real POST /token
 * call below, real JWKS fetch, and real jose jwtVerify() cryptographic check.
 *
 * Body (JSON): { email, sub, name?, nonce, email_verified? }
 * Response:    { code: "<opaque>" }
 */
async function handleIssueCode(req, res) {
  let body;
  try {
    body = JSON.parse(await readBody(req));
  } catch {
    respond(res, 400, { error: 'invalid_request', error_description: 'Body must be valid JSON' });
    return;
  }

  const { email, sub, name = null, nonce, email_verified = true } = body ?? {};

  if (!email || typeof email !== 'string') {
    respond(res, 400, { error: 'invalid_request', error_description: 'email required' });
    return;
  }
  if (!sub || typeof sub !== 'string') {
    respond(res, 400, { error: 'invalid_request', error_description: 'sub required' });
    return;
  }
  if (!nonce || typeof nonce !== 'string') {
    respond(res, 400, { error: 'invalid_request', error_description: 'nonce required' });
    return;
  }

  pruneExpired();
  const code = generateCode();
  codeStore.set(code, {
    payload: { email, sub, name, nonce, email_verified: Boolean(email_verified) },
    expiresAt: Date.now() + 2 * 60 * 1000,
  });

  respond(res, 200, { code });
}

/**
 * POST /token  —  standard OAuth2 authorization_code grant.
 *
 * WHY this is the critical path that proves real JWT validation:
 * - The backend LocalOidcSsoAdapter calls this during the SSO callback flow.
 * - This returns a REAL RS256-signed JWT (not alg:none like the FakeSsoAdapter).
 * - The backend then calls jose jwtVerify() against the JWKS fetched from
 *   GET /.well-known/jwks.json on this server.
 * - This proves end-to-end: JWKS fetch, RSA signature verification, iss/aud/exp
 *   enforcement, and nonce enforcement all run against real cryptographic material.
 *
 * Body (application/x-www-form-urlencoded):
 *   grant_type=authorization_code&code=<...>&redirect_uri=<...>
 *
 * Response: standard OAuth2 token response with id_token field.
 */
async function handleToken(req, res) {
  let params;
  try {
    params = Object.fromEntries(new URLSearchParams(await readBody(req)).entries());
  } catch {
    respond(res, 400, { error: 'invalid_request', error_description: 'Malformed body' });
    return;
  }

  if (params.grant_type !== 'authorization_code') {
    respond(res, 400, { error: 'unsupported_grant_type' });
    return;
  }
  if (!params.code) {
    respond(res, 400, { error: 'invalid_request', error_description: 'code is required' });
    return;
  }

  const entry = codeStore.get(params.code);
  if (!entry || entry.expiresAt < Date.now()) {
    codeStore.delete(params.code);
    respond(res, 400, { error: 'invalid_grant', error_description: 'Code not found or expired' });
    return;
  }

  codeStore.delete(params.code); // Single-use

  const now = Math.floor(Date.now() / 1000);
  const idTokenClaims = {
    iss: ISSUER,
    aud: CLIENT_ID,
    sub: entry.payload.sub,
    email: entry.payload.email,
    email_verified: entry.payload.email_verified,
    nonce: entry.payload.nonce,
    iat: now,
    exp: now + 300,
    ...(entry.payload.name ? { name: entry.payload.name } : {}),
  };

  respond(res, 200, {
    access_token: 'local-oidc-access-not-used',
    token_type: 'Bearer',
    expires_in: 300,
    id_token: buildIdToken(idTokenClaims),
  });
}

// ── Server ────────────────────────────────────────────────────────────────────

createServer(async (req, res) => {
  const { method } = req;
  const path = new URL(req.url ?? '/', `http://localhost:${PORT}`).pathname;

  try {
    if (method === 'GET' && path === '/.well-known/openid-configuration')
      return handleDiscovery(req, res);
    if (method === 'GET' && path === '/.well-known/jwks.json') return handleJwks(req, res);
    if (method === 'POST' && path === '/token') return await handleToken(req, res);
    if (method === 'POST' && path === '/code') return await handleIssueCode(req, res);
    respond(res, 404, { error: 'not_found', path });
  } catch (err) {
    console.error('[local-oidc] error:', err?.message ?? err);
    respond(res, 500, { error: 'server_error' });
  }
}).listen(PORT, '0.0.0.0', () => {
  console.log(`[local-oidc] Listening  port=${PORT}  issuer=${ISSUER}  client_id=${CLIENT_ID}`);
  console.log(`[local-oidc] JWKS  GET  ${ISSUER}/.well-known/jwks.json`);
  console.log(`[local-oidc] Token POST ${ISSUER}/token`);
  console.log(`[local-oidc] Code  POST ${ISSUER}/code  (CI helper only)`);
});
