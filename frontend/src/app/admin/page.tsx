/**
 * frontend/src/app/admin/page.tsx
 *
 * WHY:
 * - Minimal but real authenticated landing route for workspace admins.
 * - Only renders when backend bootstrap truth resolves to a fully-authenticated ADMIN session.
 *
 * PHASE 9 UPDATE (ADR 0003):
 * - Renders WorkspaceSetupBanner when config.tenant.setupCompleted is false.
 *   Any admin can click the banner to visit /admin/settings and complete setup.
 *   Once any admin does so, setup_completed_at is set on the tenant and the
 *   banner disappears for everyone on the next page load.
 *   No redirect occurs — all admins always land here regardless of setup state.
 */

import Link from 'next/link';
import { redirect } from 'next/navigation';
import { loadAuthBootstrap } from '@/shared/auth/bootstrap.server';
import { AuthenticatedShell } from '@/shared/auth/components/authenticated-shell';
import { WorkspaceSetupBanner } from '@/shared/auth/components/workspace-setup-banner';
import { ADMIN_INVITES_PATH, getRouteStateRedirectPath } from '@/shared/auth/redirects';

export const dynamic = 'force-dynamic';

const navLinkStyle = {
  color: '#0f172a',
  fontSize: '14px',
  fontWeight: 600,
  textDecoration: 'none',
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

  return (
    <AuthenticatedShell
      eyebrow="Hubins admin workspace"
      title="Admin dashboard"
      subtitle="Workspace admin landing. Manage invites, configure workspace settings, and monitor activity."
      me={routeState.me}
    >
      <div style={{ display: 'grid', gap: '16px' }}>
        {/* Phase 9: workspace setup banner — shown until any admin visits /admin/settings */}
        <WorkspaceSetupBanner setupCompleted={routeState.config.tenant.setupCompleted} />

        <div style={{ display: 'grid', gap: '10px' }}>
          <h2 style={{ margin: 0, fontSize: '22px', lineHeight: 1.2 }}>Admin landing ready</h2>
          <p style={{ margin: 0, fontSize: '15px', lineHeight: 1.7, color: '#475569' }}>
            Admin users are separated from members at the route-state layer so the root gate lands
            them in <code>/admin</code> instead of the member app.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
          <Link href={ADMIN_INVITES_PATH} style={navLinkStyle}>
            → Manage invites
          </Link>
        </div>
      </div>
    </AuthenticatedShell>
  );
}
