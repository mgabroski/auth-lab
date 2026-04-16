import type { NextConfig } from 'next';
import path from 'path';

const nodeEnv = process.env.NODE_ENV ?? 'development';
const internalApiUrl = process.env.INTERNAL_API_URL;

if (nodeEnv !== 'development' && !internalApiUrl) {
  throw new Error(
    [
      'STARTUP ERROR: INTERNAL_API_URL is not set.',
      `NODE_ENV is '${nodeEnv}'. In non-development environments, INTERNAL_API_URL`,
      'must be explicitly configured for the Control Plane (for example',
      'http://backend:3001 in Docker Compose or the backend service URL in your',
      'deployment platform).',
      '',
      'Without it, CP SSR and Route Handlers fall back to localhost:3001, which',
      'breaks inside containers and produces runtime 500s instead of a fail-fast',
      'startup error.',
    ].join('\n'),
  );
}

const nextConfig: NextConfig = {
  output: 'standalone',
  outputFileTracingRoot: path.join(__dirname, '../'),
};

export default nextConfig;
