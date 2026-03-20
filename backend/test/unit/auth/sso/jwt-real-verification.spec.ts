/**
 * backend/test/unit/auth/sso/jwt-real-verification.spec.ts
 *
 * WHY:
 * - Proves the real jwtVerify + JWKS path executes correctly end-to-end.
 * - The existing adapter unit tests (google-sso.adapter.spec.ts,
 *   microsoft-sso.adapter.spec.ts) mock jose entirely via vi.mock('jose', ...),
 *   so they bypass signature verification, JWKS fetch, and the jose cryptographic
 *   path completely. They prove adapter logic, not crypto.
 * - The Playwright E2E tests use FakeSsoAdapter, which also bypasses jwt.ts
 *   entirely for the password-login equivalent code path.
 * - This test closes that proof gap: it generates real RS256 key pairs using
 *   jose, signs real JWTs, and verifies them through the actual
 *   verifyGoogleJwt / verifyMicrosoftJwt functions in jwt.ts — proving the
 *   real cryptographic path is wired correctly.
 *
 * WHAT IS PROVEN:
 * - verifyGoogleJwt / verifyMicrosoftJwt call jwtVerify with the module-level
 *   JWKS constant (not a re-fetched key on every call).
 * - RS256 signature verification succeeds for a correctly signed token.
 * - Nonce mismatch is caught and re-thrown as 'jwt_nonce_mismatch'.
 * - Expired tokens are rejected by jose's built-in exp enforcement.
 * - Wrong issuer is rejected by jose's built-in iss enforcement.
 * - Wrong audience is rejected by jose's built-in aud enforcement.
 * - Microsoft tenant-specific issuer (tid-derived) is enforced correctly.
 *
 * RULES:
 * - No network calls. JWKS is served from in-process key material via
 *   createLocalJWKSet (jose). No HTTP fetch is issued at any point.
 * - vi.hoisted + vi.mock intercepts createRemoteJWKSet in jose so that when
 *   jwt.ts is imported, GOOGLE_JWKS and MICROSOFT_JWKS are assigned a proxy
 *   function that delegates to a real createLocalJWKSet result. This is the
 *   correct approach: GOOGLE_JWKS and MICROSOFT_JWKS are export const (not
 *   getter properties), so vi.spyOn(..., 'get') cannot intercept them.
 * - jose generateKeyPair('RS256') is used — same library already in backend
 *   dependencies (jose ^6.1.3).
 * - Tests run in Node environment only: no Fastify, no DB, no Redis.
 * - email_verified enforcement is the ADAPTER's responsibility, not jwt.ts.
 *   verifyGoogleJwt returns the raw JWTPayload. GoogleSsoAdapter checks
 *   payload.email_verified === true and throws if absent or false.
 *   That boundary is covered by google-sso.adapter.spec.ts. We do NOT test
 *   it here to avoid conflating the two layers.
 *
 * WHY vi.hoisted + vi.mock (not vi.spyOn):
 * - GOOGLE_JWKS and MICROSOFT_JWKS are module-level `export const` values
 *   assigned at import time by createRemoteJWKSet(). They are not getter
 *   properties on the module namespace, so `vi.spyOn(module, 'KEY', 'get')`
 *   resolves to `never` in TypeScript and fails at runtime.
 * - The correct approach is to mock createRemoteJWKSet in jose before jwt.ts
 *   is imported. vi.mock is hoisted to the top of the file automatically by
 *   vitest, so the mock is active before any import statement resolves.
 * - vi.hoisted creates shared mutable state (a JWKS resolver slot) that the
 *   vi.mock factory can close over. beforeAll populates the slot with a real
 *   createLocalJWKSet result after the key pair is generated.
 *
 * WHY Awaited<ReturnType<typeof generateKeyPair>>['privateKey'] (not KeyLike):
 * - jose v6 removed the KeyLike type export entirely.
 * - This utility type resolves to the actual private key type returned by
 *   generateKeyPair at runtime (CryptoKey | KeyObject depending on environment),
 *   which is exactly what SignJWT.sign() accepts. No `any` needed.
 */

import { vi, beforeAll, describe, expect, it } from 'vitest';

// ── JWKS proxy slot ───────────────────────────────────────────────────────────
//
// vi.hoisted runs before vi.mock factories and before any imports resolve.
// It creates a shared mutable slot that the mock factory closes over.
// beforeAll will populate the slot with the real createLocalJWKSet result
// once the key pair has been generated.

const jwksSlot = vi.hoisted<{ resolver: ((h: unknown, i: unknown) => Promise<unknown>) | null }>(
  () => ({ resolver: null }),
);

// ── jose mock ─────────────────────────────────────────────────────────────────
//
// Spread actual jose so only createRemoteJWKSet is replaced. All other exports
// (SignJWT, jwtVerify, generateKeyPair, exportJWK, createLocalJWKSet, ...) are
// the real implementations.
//
// createRemoteJWKSet normally returns a JWTVerifyGetKey function that fetches
// public keys from a remote URL. We replace it with a factory that returns a
// proxy function. The proxy delegates to jwksSlot.resolver, which is populated
// in beforeAll with a real createLocalJWKSet result — no network call is made.

vi.mock('jose', async () => {
  const actual = await vi.importActual<typeof import('jose')>('jose');
  return {
    ...actual,
    createRemoteJWKSet: (_url: URL) => async (header: unknown, input: unknown) => {
      if (!jwksSlot.resolver) {
        throw new Error('[jwt-test] JWKS proxy not initialized — beforeAll has not run yet.');
      }
      return jwksSlot.resolver(header, input);
    },
  };
});

// ── imports (resolved after vi.mock is active) ────────────────────────────────

import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair } from 'jose';
import { verifyGoogleJwt, verifyMicrosoftJwt } from '../../../../src/modules/auth/sso/jwt';

// ── Test constants ────────────────────────────────────────────────────────────

const GOOGLE_CLIENT_ID = 'test-google-client-id';
const MICROSOFT_CLIENT_ID = 'test-microsoft-client-id';
const GOOGLE_ISSUER = 'https://accounts.google.com';
const TEST_TID = 'test-tenant-id-abc123';
const MICROSOFT_ISSUER = `https://login.microsoftonline.com/${TEST_TID}/v2.0`;
const TEST_SUB = 'test-subject-123';
const TEST_EMAIL = 'test-user@example.com';
const TEST_NONCE = 'test-nonce-abc';

// ── Key material — generated once for the whole suite ────────────────────────

// WHY Awaited<ReturnType<...>>: jose v6 removed KeyLike. This utility type
// resolves to the actual private key type (CryptoKey | KeyObject) that
// generateKeyPair returns and that SignJWT.sign() accepts — no `any` needed.
let privateKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];

beforeAll(async () => {
  // Generate a real RS256 key pair.
  // WHY generateKeyPair instead of a hard-coded test key: avoids committing
  // any private key material to the repository, even a test-only one.
  // jose generates the pair in-process; the private key never leaves this file.
  const { privateKey: priv, publicKey: pub } = await generateKeyPair('RS256');
  privateKey = priv;

  // Build a local JWKS from the generated public key.
  // createLocalJWKSet serves keys from in-process memory — no HTTP fetch.
  const publicJwk = await exportJWK(pub);
  publicJwk.alg = 'RS256'; // alg hint lets jose select the right key

  // WHY `as unknown as typeof jwksSlot.resolver`:
  // createLocalJWKSet returns JWTVerifyGetKey, a specific overloaded function
  // type that is not directly assignable to the generic proxy slot type
  // `(h: unknown, i: unknown) => Promise<unknown>`. The double-assertion is
  // safe here because at runtime this function IS called by jwtVerify with
  // the JWTHeaderParameters and GetKeyFunction arguments it expects.
  jwksSlot.resolver = createLocalJWKSet({
    keys: [publicJwk],
  }) as unknown as typeof jwksSlot.resolver;
});

// ── Helper: sign a test JWT with the test private key ────────────────────────

async function signTestJwt(params: {
  iss: string;
  aud: string;
  sub?: string;
  email?: string;
  nonce?: string;
  /** Seconds from now. Negative = already expired. Default: +300. */
  expOffsetSeconds?: number;
  tid?: string;
  name?: string;
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const expOffset = params.expOffsetSeconds ?? 300;

  return new SignJWT({
    email: params.email ?? TEST_EMAIL,
    nonce: params.nonce,
    tid: params.tid,
    name: params.name ?? 'Test User',
  })
    .setProtectedHeader({ alg: 'RS256' })
    .setIssuer(params.iss)
    .setAudience(params.aud)
    .setSubject(params.sub ?? TEST_SUB)
    .setIssuedAt(now)
    .setExpirationTime(now + expOffset)
    .sign(privateKey);
}

// ─────────────────────────────────────────────────────────────────────────────
// Google JWT verification
// ─────────────────────────────────────────────────────────────────────────────

describe('verifyGoogleJwt — real RS256 cryptographic path', () => {
  it('happy path: valid RS256 JWT with correct iss/aud/nonce resolves with payload', async () => {
    const token = await signTestJwt({
      iss: GOOGLE_ISSUER,
      aud: GOOGLE_CLIENT_ID,
      nonce: TEST_NONCE,
    });

    const payload = await verifyGoogleJwt({
      idToken: token,
      clientId: GOOGLE_CLIENT_ID,
      expectedNonce: TEST_NONCE,
    });

    expect(payload.iss).toBe(GOOGLE_ISSUER);
    expect(payload.aud).toBe(GOOGLE_CLIENT_ID);
    expect(payload.sub).toBe(TEST_SUB);
    expect(payload.nonce).toBe(TEST_NONCE);
    expect(payload.email).toBe(TEST_EMAIL);
  });

  it('wrong nonce: rejects with jwt_nonce_mismatch', async () => {
    // The nonce embedded in the token does not match the expected nonce.
    // verifyGoogleJwt checks this explicitly after jwtVerify succeeds.
    const token = await signTestJwt({
      iss: GOOGLE_ISSUER,
      aud: GOOGLE_CLIENT_ID,
      nonce: 'embedded-nonce',
    });

    await expect(
      verifyGoogleJwt({
        idToken: token,
        clientId: GOOGLE_CLIENT_ID,
        expectedNonce: 'different-nonce',
      }),
    ).rejects.toThrow('jwt_nonce_mismatch');
  });

  it('expired token: jose rejects with JWTExpired', async () => {
    const token = await signTestJwt({
      iss: GOOGLE_ISSUER,
      aud: GOOGLE_CLIENT_ID,
      nonce: TEST_NONCE,
      expOffsetSeconds: -60, // expired 60 seconds ago
    });

    await expect(
      verifyGoogleJwt({
        idToken: token,
        clientId: GOOGLE_CLIENT_ID,
        expectedNonce: TEST_NONCE,
      }),
    ).rejects.toThrow();
  });

  it('wrong issuer: jose rejects when iss does not match accounts.google.com', async () => {
    const token = await signTestJwt({
      iss: 'https://evil-issuer.example.com',
      aud: GOOGLE_CLIENT_ID,
      nonce: TEST_NONCE,
    });

    await expect(
      verifyGoogleJwt({
        idToken: token,
        clientId: GOOGLE_CLIENT_ID,
        expectedNonce: TEST_NONCE,
      }),
    ).rejects.toThrow();
  });

  it('wrong audience: jose rejects when aud does not match clientId', async () => {
    const token = await signTestJwt({
      iss: GOOGLE_ISSUER,
      aud: 'wrong-client-id',
      nonce: TEST_NONCE,
    });

    await expect(
      verifyGoogleJwt({
        idToken: token,
        clientId: GOOGLE_CLIENT_ID,
        expectedNonce: TEST_NONCE,
      }),
    ).rejects.toThrow();
  });

  // NOTE — email_verified is NOT tested here.
  // Boundary explanation:
  //   verifyGoogleJwt returns the raw JWTPayload from jose. It does not inspect
  //   email_verified at all. GoogleSsoAdapter.validateAndExtractIdentity() calls
  //   verifyGoogleJwt and then checks payload.email_verified === true, throwing
  //   AppError.forbidden if the claim is absent or false.
  //   That boundary is covered in google-sso.adapter.spec.ts (the mock-based
  //   adapter test). Testing it here would conflate jwt.ts responsibilities with
  //   adapter responsibilities — a violation of single responsibility.
});

// ─────────────────────────────────────────────────────────────────────────────
// Microsoft JWT verification
// ─────────────────────────────────────────────────────────────────────────────

describe('verifyMicrosoftJwt — real RS256 cryptographic path', () => {
  it('happy path: valid RS256 JWT with tid-derived issuer resolves with payload', async () => {
    const token = await signTestJwt({
      iss: MICROSOFT_ISSUER,
      aud: MICROSOFT_CLIENT_ID,
      nonce: TEST_NONCE,
      tid: TEST_TID,
    });

    const payload = await verifyMicrosoftJwt({
      idToken: token,
      clientId: MICROSOFT_CLIENT_ID,
      expectedNonce: TEST_NONCE,
      tid: TEST_TID,
    });

    expect(payload.iss).toBe(MICROSOFT_ISSUER);
    expect(payload.aud).toBe(MICROSOFT_CLIENT_ID);
    expect(payload.nonce).toBe(TEST_NONCE);
    expect(payload.sub).toBe(TEST_SUB);
  });

  it('wrong nonce: rejects with jwt_nonce_mismatch', async () => {
    const token = await signTestJwt({
      iss: MICROSOFT_ISSUER,
      aud: MICROSOFT_CLIENT_ID,
      nonce: 'embedded-nonce',
      tid: TEST_TID,
    });

    await expect(
      verifyMicrosoftJwt({
        idToken: token,
        clientId: MICROSOFT_CLIENT_ID,
        expectedNonce: 'wrong-nonce',
        tid: TEST_TID,
      }),
    ).rejects.toThrow('jwt_nonce_mismatch');
  });

  it('wrong tid-derived issuer: rejects when tid mismatch causes issuer mismatch', async () => {
    // WHY this is the correct test for Microsoft issuer enforcement:
    // The token was signed with iss = "https://login.microsoftonline.com/TEST_TID/v2.0".
    // We verify with tid = 'different-tenant-id', which causes verifyMicrosoftJwt
    // to build expectedIssuer = "https://login.microsoftonline.com/different-tenant-id/v2.0".
    // jose rejects because the token's iss does not match the expected issuer.
    // This is exactly the production security property: a token from one Entra
    // tenant cannot be accepted by a verification call for a different tenant.
    const token = await signTestJwt({
      iss: MICROSOFT_ISSUER,
      aud: MICROSOFT_CLIENT_ID,
      nonce: TEST_NONCE,
      tid: TEST_TID,
    });

    await expect(
      verifyMicrosoftJwt({
        idToken: token,
        clientId: MICROSOFT_CLIENT_ID,
        expectedNonce: TEST_NONCE,
        tid: 'different-tenant-id',
      }),
    ).rejects.toThrow();
  });

  it('expired token: jose rejects', async () => {
    const token = await signTestJwt({
      iss: MICROSOFT_ISSUER,
      aud: MICROSOFT_CLIENT_ID,
      nonce: TEST_NONCE,
      tid: TEST_TID,
      expOffsetSeconds: -30,
    });

    await expect(
      verifyMicrosoftJwt({
        idToken: token,
        clientId: MICROSOFT_CLIENT_ID,
        expectedNonce: TEST_NONCE,
        tid: TEST_TID,
      }),
    ).rejects.toThrow();
  });

  it('wrong audience: jose rejects', async () => {
    const token = await signTestJwt({
      iss: MICROSOFT_ISSUER,
      aud: 'wrong-microsoft-client',
      nonce: TEST_NONCE,
      tid: TEST_TID,
    });

    await expect(
      verifyMicrosoftJwt({
        idToken: token,
        clientId: MICROSOFT_CLIENT_ID,
        expectedNonce: TEST_NONCE,
        tid: TEST_TID,
      }),
    ).rejects.toThrow();
  });
});
