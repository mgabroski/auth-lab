import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import type { ReactNode } from 'react';

// WHY:
// - CP is a permanent application surface, but no-auth CP access is temporary.
// - Backend route registration is controlled by CP_ENABLED, while auth policy is
//   controlled by CP_AUTH_MODE. The CP frontend must use the same enablement
//   vocabulary or the backend can be healthy while the CP app returns a 404.
// - CP_NO_AUTH_ALLOWED is kept only as a deprecated compatibility alias for
//   older local/CI env files.
export const dynamic = 'force-dynamic';
export const revalidate = 0;

export const metadata: Metadata = {
  title: 'Hubins Control Plane',
  description: 'Internal Control Plane shell for account creation and setup.',
};

function parseEnvBoolean(value: string | undefined): boolean | undefined {
  if (value === 'true') return true;
  if (value === 'false') return false;
  return undefined;
}

function isControlPlaneEnabled(): boolean {
  const nodeEnv = process.env.NODE_ENV ?? 'development';

  const explicitCpEnabled = parseEnvBoolean(process.env.CP_ENABLED);
  if (explicitCpEnabled !== undefined) {
    return explicitCpEnabled;
  }

  // Deprecated compatibility bridge for older local/CI env files.
  const legacyNoAuthAllowed = parseEnvBoolean(process.env.CP_NO_AUTH_ALLOWED);
  if (legacyNoAuthAllowed !== undefined) {
    return legacyNoAuthAllowed;
  }

  // Host-run local development stays ergonomic even before env files are created.
  // Docker/full-stack CI should set CP_ENABLED explicitly.
  return nodeEnv === 'development';
}

export default function RootLayout({ children }: { children: ReactNode }) {
  if (!isControlPlaneEnabled()) {
    notFound();
  }

  return (
    <html lang="en">
      <head />
      <body>{children}</body>
    </html>
  );
}
