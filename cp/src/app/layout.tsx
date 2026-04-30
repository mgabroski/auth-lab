import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import type { ReactNode } from 'react';

// WHY:
// - This layout reads CP_NO_AUTH_ALLOWED at runtime so Docker full-stack CP does not bake a build-time 404.
export const dynamic = 'force-dynamic';

export const metadata: Metadata = {
  title: 'Hubins Control Plane',
  description: 'Internal Control Plane shell for account creation and setup.',
};

function isControlPlaneEnabled(): boolean {
  const nodeEnv = process.env.NODE_ENV ?? 'development';

  if (nodeEnv === 'development') {
    return true;
  }

  return process.env.CP_NO_AUTH_ALLOWED === 'true';
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
