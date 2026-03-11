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
 */

import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  output: 'standalone',
};

export default nextConfig;
