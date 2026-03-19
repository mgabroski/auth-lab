/**
 * frontend/next.config.ts
 *
 * WHY:
 * - `output: 'standalone'` produces a self-contained Docker image for stack/prod-ish runs.
 * - Browser same-origin `/api/*` is now handled in host-run mode by a local Next.js
 *   Route Handler proxy (`src/app/api/[...path]/route.ts`), not by rewrites.
 *
 * HOST-RUN DEV MODE (yarn dev):
 * - Browser → Next.js `/api/*` Route Handler → backend
 * - This preserves the original tenant-bearing Host header instead of depending on
 *   opaque rewrite behaviour.
 * - SSR still calls the backend directly through INTERNAL_API_URL.
 *
 * STACK / PRODUCTION-LIKE MODE:
 * - Public reverse proxies (Caddy/nginx) route `/api/*` directly to the backend.
 * - The frontend Route Handler exists as a host-run compatibility shim; it is not the
 *   intended public topology path in deployed environments.
 *
 * 9/10 HARDENING:
 * - Added INTERNAL_API_URL startup validation.
 *   Without INTERNAL_API_URL, SSR falls back to 'http://backend:3001' which does
 *   not resolve outside Docker. In non-development environments, a missing
 *   INTERNAL_API_URL is a misconfiguration — the process now fails at startup
 *   with a clear error instead of producing runtime 500s on every SSR page.
 */

import type { NextConfig } from 'next';
import path from 'path';

// ── Startup validation ────────────────────────────────────────────────────────

const nodeEnv = process.env.NODE_ENV ?? 'development';
const internalApiUrl = process.env.INTERNAL_API_URL;

if (nodeEnv !== 'development' && !internalApiUrl) {
  throw new Error(
    [
      'STARTUP ERROR: INTERNAL_API_URL is not set.',
      `NODE_ENV is '${nodeEnv}'. In non-development environments, INTERNAL_API_URL`,
      'must be explicitly configured (e.g. http://backend:3001 in Docker Compose,',
      'or the backend service URL in your deployment platform).',
      '',
      'Without it, SSR falls back to http://backend:3001 which does not resolve',
      'in environments where the backend is not on that internal hostname.',
    ].join('\n'),
  );
}

// ─────────────────────────────────────────────────────────────────────────────

const nextConfig: NextConfig = {
  output: 'standalone',
  // WHY: In a Yarn workspace, Next.js traces files relative to the repo root
  // by default, which causes the standalone output to nest server.js under a
  // subdirectory path. Setting outputFileTracingRoot to the repo root (one level
  // up from this file) tells Next.js exactly where the workspace root is, which
  // produces server.js at the expected root of .next/standalone/ so the
  // Dockerfile COPY + CMD ["node", "server.js"] resolves correctly.
  outputFileTracingRoot: path.join(__dirname, '../'),
};

export default nextConfig;
