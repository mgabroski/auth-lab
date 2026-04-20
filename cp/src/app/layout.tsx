import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import type { ReactNode } from 'react';

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
