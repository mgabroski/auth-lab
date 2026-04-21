/**
 * frontend/src/app/admin/page.tsx
 *
 * WHY:
 * - Minimal but real authenticated landing route for workspace admins.
 * - Uses auth bootstrap only for session/role routing, then uses
 *   `GET /settings/bootstrap` as the sole Settings bootstrap-safe truth.
 * - Preserves the locked contract that `/admin` may show only a non-blocking
 *   banner and a generic CTA into `/admin/settings`.
 */
import React from 'react';
import Link from 'next/link';
import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthenticatedShell } from '@/shared/auth/components/authenticated-shell';
import { WorkspaceSetupBanner } from '@/shared/auth/components/workspace-setup-banner';
import { ADMIN_INVITES_PATH, getRouteStateRedirectPath } from '@/shared/auth/redirects';
import { loadSettingsBootstrap } from '@/shared/settings/loaders';

export const dynamic = 'force-dynamic';

const navLinkStyle = {
  color: '#0f172a',
  fontSize: '14px',
  fontWeight: 600,
  textDecoration: 'none',
} as const;

const errorCardStyle = {
  display: 'grid',
  gap: '8px',
  padding: '16px 18px',
  borderRadius: '16px',
  border: '1px solid #fecaca',
  backgroundColor: '#fef2f2',
  color: '#991b1b',
} as const;

export default async function AdminPage() {
  const bootstrap = await loadAuthBootstrap();

  if (!bootstrap.ok) {
    return (
      <main>
        <h1>Hubins — Admin</h1>
        <p>Bootstrap failed while loading the admin landing route.</p>
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

  const settingsBootstrap = await loadSettingsBootstrap();

  return (
    <AuthenticatedShell
      eyebrow="Hubins admin workspace"
      title="Admin dashboard"
      subtitle="Workspace admin landing. Manage invites, open Settings, and monitor the current workspace."
      me={routeState.me}
    >
      <div style={{ display: 'grid', gap: '16px' }}>
        {settingsBootstrap.ok ? (
          <WorkspaceSetupBanner showSetupBanner={settingsBootstrap.data.showSetupBanner} />
        ) : (
          <div role="alert" style={errorCardStyle}>
            <strong>Workspace settings status is unavailable.</strong>
            <span>
              The admin landing route did not receive a valid response from{' '}
              <code>GET /settings/bootstrap</code>.
            </span>
            <span>{settingsBootstrap.error.message}</span>
          </div>
        )}

        <div style={{ display: 'grid', gap: '10px' }}>
          <h2 style={{ margin: 0, fontSize: '22px', lineHeight: 1.2 }}>Admin landing ready</h2>
          <p style={{ margin: 0, fontSize: '15px', lineHeight: 1.7, color: '#475569' }}>
            Admin users are separated from members at the route-state layer so the root gate lands
            them in <code>/admin</code> instead of the member app.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
          <Link href="/admin/settings" style={navLinkStyle}>
            → Open workspace settings
          </Link>
          <Link href={ADMIN_INVITES_PATH} style={navLinkStyle}>
            → Manage invites
          </Link>
        </div>
      </div>
    </AuthenticatedShell>
  );
}
