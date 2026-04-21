/**
 * frontend/src/app/admin/settings/access/page.tsx
 *
 * WHY:
 * - Ships the first real Settings section page in the tenant admin surface.
 * - Uses the backend-owned Access DTO and explicit acknowledge action instead of
 *   placeholder shell copy.
 * - Preserves the locked contract that Access is read-only in v1 and completes
 *   only through explicit acknowledgement.
 */

import React from 'react';
import Link from 'next/link';
import { redirect } from 'next/navigation';

import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthenticatedShell } from '@/shared/auth/components/authenticated-shell';
import {
  ADMIN_SETTINGS_PATH,
  AUTHENTICATED_ADMIN_ENTRY_PATH,
  getRouteStateRedirectPath,
} from '@/shared/auth/redirects';
import { loadAccessSettings } from '@/shared/settings/loaders';
import { AccessSettingsReview } from '@/shared/settings/components/access-settings-review';

const navLinkStyle = {
  color: '#0f172a',
  fontSize: '14px',
  fontWeight: 600,
  textDecoration: 'none',
} as const;

const errorCardStyle = {
  display: 'grid',
  gap: '8px',
  padding: '18px 20px',
  borderRadius: '20px',
  border: '1px solid #fecaca',
  backgroundColor: '#fef2f2',
  color: '#991b1b',
} as const;

export const dynamic = 'force-dynamic';

export default async function AdminSettingsAccessPage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <main>
        <h1>Hubins — Access &amp; Security</h1>
        <p>Bootstrap failed while loading the settings route.</p>
        <p>
          <strong>Error:</strong> {bootstrap.error.message}
        </p>
      </main>
    );
  }

  const routeState = bootstrap.routeState;

  if (routeState.kind !== 'AUTHENTICATED_ADMIN') {
    redirect(getRouteStateRedirectPath(routeState));
  }

  const access = await loadAccessSettings();

  return (
    <AuthenticatedShell
      eyebrow="Hubins admin workspace"
      title="Access & Security"
      subtitle="Review the platform-managed access envelope, including blockers, warnings, and the explicit acknowledge action required in v1."
      me={routeState.me}
    >
      <div style={{ display: 'grid', gap: '16px' }}>
        <div style={{ display: 'grid', gap: '10px' }}>
          <Link href={ADMIN_SETTINGS_PATH} style={navLinkStyle}>
            ← Back to workspace settings
          </Link>
          <Link href={AUTHENTICATED_ADMIN_ENTRY_PATH} style={navLinkStyle}>
            ← Back to admin dashboard
          </Link>
        </div>

        {access.ok ? (
          <AccessSettingsReview initialData={access.data} />
        ) : (
          <section style={errorCardStyle}>
            <h2 style={{ margin: 0, fontSize: '20px', lineHeight: 1.2 }}>
              Access &amp; Security is unavailable
            </h2>
            <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7 }}>
              The frontend could not load <code>GET /settings/access</code>, so it is not rendering
              placeholder or fallback truth.
            </p>
            <p style={{ margin: 0, fontSize: '14px', lineHeight: 1.7 }}>{access.error.message}</p>
          </section>
        )}
      </div>
    </AuthenticatedShell>
  );
}
